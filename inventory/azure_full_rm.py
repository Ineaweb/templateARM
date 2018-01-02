#!/usr/bin/env python

# Python
import argparse
import json
import os
import re
import sys
import inspect

try:
    # python2
    import ConfigParser as cp
except ImportError:
    # python3
    import configparser as cp

from packaging.version import Version

from os.path import expanduser
import ansible.module_utils.six.moves.urllib.parse as urlparse

HAS_AZURE = True
HAS_AZURE_EXC = None

try:
    from msrestazure.azure_exceptions import CloudError
    from msrestazure import azure_cloud
    from azure.mgmt.compute import __version__ as azure_compute_version
    from azure.common import AzureMissingResourceHttpError, AzureHttpError
    from azure.common.credentials import ServicePrincipalCredentials, UserPassCredentials
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.resource.resources import ResourceManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.web import WebSiteManagementClient
    from azure.mgmt.redis import RedisManagementClient
except ImportError as exc:
    HAS_AZURE_EXC = exc
    HAS_AZURE = False


AZURE_CREDENTIAL_ENV_MAPPING = dict(
    profile='AZURE_PROFILE',
    subscription_id='AZURE_SUBSCRIPTION_ID',
    client_id='AZURE_CLIENT_ID',
    secret='AZURE_SECRET',
    tenant='AZURE_TENANT',
    ad_user='AZURE_AD_USER',
    password='AZURE_PASSWORD',
    cloud_environment='AZURE_CLOUD_ENVIRONMENT',
)

AZURE_CONFIG_SETTINGS = dict(
    resource_groups='AZURE_RESOURCE_GROUPS',
    tags='AZURE_TAGS',
    locations='AZURE_LOCATIONS',
    include_powerstate='AZURE_INCLUDE_POWERSTATE',
    group_by_resource_group='AZURE_GROUP_BY_RESOURCE_GROUP',
    group_by_location='AZURE_GROUP_BY_LOCATION',
    group_by_security_group='AZURE_GROUP_BY_SECURITY_GROUP',
    group_by_tag='AZURE_GROUP_BY_TAG'
)

AZURE_MIN_VERSION = "2.0.0"


def azure_id_to_dict(id):
    pieces = re.sub(r'^\/', '', id).split('/')
    result = {}
    index = 0
    while index < len(pieces) - 1:
        result[pieces[index]] = pieces[index + 1]
        index += 1
    return result


class AzureRM(object):

    def __init__(self, args):
        self._args = args
        self._cloud_environment = None
        self._compute_client = None
        self._webapp_client = None
        self._redis_client = None
        self._resource_client = None
        self._network_client = None

        self.debug = False
        if args.debug:
            self.debug = True

        self.credentials = self._get_credentials(args)
        if not self.credentials:
            self.fail("Failed to get credentials. Either pass as parameters, set environment variables, "
                      "or define a profile in ~/.azure/credentials.")

        # if cloud_environment specified, look up/build Cloud object
        raw_cloud_env = self.credentials.get('cloud_environment')
        if not raw_cloud_env:
            self._cloud_environment = azure_cloud.AZURE_PUBLIC_CLOUD  # SDK default
        else:
            # try to look up "well-known" values via the name attribute on azure_cloud members
            all_clouds = [x[1] for x in inspect.getmembers(azure_cloud) if isinstance(x[1], azure_cloud.Cloud)]
            matched_clouds = [x for x in all_clouds if x.name == raw_cloud_env]
            if len(matched_clouds) == 1:
                self._cloud_environment = matched_clouds[0]
            elif len(matched_clouds) > 1:
                self.fail("Azure SDK failure: more than one cloud matched for cloud_environment name '{0}'".format(raw_cloud_env))
            else:
                if not urlparse.urlparse(raw_cloud_env).scheme:
                    self.fail("cloud_environment must be an endpoint discovery URL or one of {0}".format([x.name for x in all_clouds]))
                try:
                    self._cloud_environment = azure_cloud.get_cloud_from_metadata_endpoint(raw_cloud_env)
                except Exception as e:
                    self.fail("cloud_environment {0} could not be resolved: {1}".format(raw_cloud_env, e.message))

        if self.credentials.get('subscription_id', None) is None:
            self.fail("Credentials did not include a subscription_id value.")
        self.log("setting subscription_id")
        self.subscription_id = self.credentials['subscription_id']

        if self.credentials.get('client_id') is not None and \
           self.credentials.get('secret') is not None and \
           self.credentials.get('tenant') is not None:
            self.azure_credentials = ServicePrincipalCredentials(client_id=self.credentials['client_id'],
                                                                 secret=self.credentials['secret'],
                                                                 tenant=self.credentials['tenant'],
                                                                 cloud_environment=self._cloud_environment)
        elif self.credentials.get('ad_user') is not None and self.credentials.get('password') is not None:
            tenant = self.credentials.get('tenant')
            if not tenant:
                tenant = 'common'
            self.azure_credentials = UserPassCredentials(self.credentials['ad_user'],
                                                         self.credentials['password'],
                                                         tenant=tenant,
                                                         cloud_environment=self._cloud_environment)
        else:
            self.fail("Failed to authenticate with provided credentials. Some attributes were missing. "
                      "Credentials must include client_id, secret and tenant or ad_user and password.")

    def log(self, msg):
        if self.debug:
            print(msg + u'\n')

    def fail(self, msg):
        raise Exception(msg)

    def _get_profile(self, profile="default"):
        path = expanduser("~")
        path += "/.azure/credentials"
        try:
            config = cp.ConfigParser()
            config.read(path)
        except Exception as exc:
            self.fail("Failed to access {0}. Check that the file exists and you have read "
                      "access. {1}".format(path, str(exc)))
        credentials = dict()
        for key in AZURE_CREDENTIAL_ENV_MAPPING:
            try:
                credentials[key] = config.get(profile, key, raw=True)
            except:
                pass

        if credentials.get('client_id') is not None or credentials.get('ad_user') is not None:
            return credentials

        return None

    def _get_env_credentials(self):
        env_credentials = dict()
        for attribute, env_variable in AZURE_CREDENTIAL_ENV_MAPPING.items():
            env_credentials[attribute] = os.environ.get(env_variable, None)

        if env_credentials['profile'] is not None:
            credentials = self._get_profile(env_credentials['profile'])
            return credentials

        if env_credentials['client_id'] is not None or env_credentials['ad_user'] is not None:
            return env_credentials

        return None

    def _get_credentials(self, params):
        # Get authentication credentials.
        # Precedence: cmd line parameters-> environment variables-> default profile in ~/.azure/credentials.

        self.log('Getting credentials')

        arg_credentials = dict()
        for attribute, env_variable in AZURE_CREDENTIAL_ENV_MAPPING.items():
            arg_credentials[attribute] = getattr(params, attribute)

        # try module params
        if arg_credentials['profile'] is not None:
            self.log('Retrieving credentials with profile parameter.')
            credentials = self._get_profile(arg_credentials['profile'])
            return credentials

        if arg_credentials['client_id'] is not None:
            self.log('Received credentials from parameters.')
            return arg_credentials

        if arg_credentials['ad_user'] is not None:
            self.log('Received credentials from parameters.')
            return arg_credentials

        # try environment
        env_credentials = self._get_env_credentials()
        if env_credentials:
            self.log('Received credentials from env.')
            return env_credentials

        # try default profile from ~./azure/credentials
        default_credentials = self._get_profile()
        if default_credentials:
            self.log('Retrieved default profile credentials from ~/.azure/credentials.')
            return default_credentials

        return None

    def _register(self, key):
        try:
            # We have to perform the one-time registration here. Otherwise, we receive an error the first
            # time we attempt to use the requested client.
            resource_client = self.rm_client
            resource_client.providers.register(key)
        except Exception as exc:
            self.log("One-time registration of {0} failed - {1}".format(key, str(exc)))
            self.log("You might need to register {0} using an admin account".format(key))
            self.log(("To register a provider using the Python CLI: "
                      "https://docs.microsoft.com/azure/azure-resource-manager/"
                      "resource-manager-common-deployment-errors#noregisteredproviderfound"))

    @property
    def network_client(self):
        self.log('Getting network client')
        if not self._network_client:
            self._network_client = NetworkManagementClient(
                self.azure_credentials,
                self.subscription_id,
                base_url=self._cloud_environment.endpoints.resource_manager
            )
            self._register('Microsoft.Network')
        return self._network_client

    @property
    def rm_client(self):
        self.log('Getting resource manager client')
        if not self._resource_client:
            self._resource_client = ResourceManagementClient(
                self.azure_credentials,
                self.subscription_id,
                base_url=self._cloud_environment.endpoints.resource_manager,
                api_version='2017-05-10'
            )
        return self._resource_client
        
    @property
    def webapp_client(self):
        self.log('Getting webapp client')
        if not self._webapp_client:
            self._webapp_client = WebSiteManagementClient(
                self.azure_credentials,
                self.subscription_id,
                base_url=self._cloud_environment.endpoints.resource_manager
            )
            self._register('Microsoft.Web/sites')
        return self._webapp_client

    @property
    def compute_client(self):
        self.log('Getting compute client')
        if not self._compute_client:
	    self._compute_client = ComputeManagementClient(
                self.azure_credentials,
                self.subscription_id,
                base_url=self._cloud_environment.endpoints.resource_manager
            )
            self._register('Microsoft.Compute')
        return self._compute_client

    @property
    def redis_client(self):
        self.log('Getting redis client')
        if not self._redis_client:
	    self._redis_client = RedisManagementClient(
                self.azure_credentials,
                self.subscription_id,
                base_url=self._cloud_environment.endpoints.resource_manager
			)
            self._register('Microsoft.Redis')
        return self._redis_client        


class AzureInventory(object):

    def __init__(self):

        self._args = self._parse_cli_args()

        try:
            rm = AzureRM(self._args)
        except Exception as e:
            sys.exit("{0}".format(str(e)))

        self._compute_client = rm.compute_client
        self._redis_client = rm.redis_client
        self._webapp_client = rm.webapp_client
        self._network_client = rm.network_client
        self._resource_client = rm.rm_client
        self._security_groups = None

        self.resource_groups = []
        self.tags = None
        self.locations = None
        self.replace_dash_in_groups = False
        self.group_by_resource_group = True
        self.group_by_location = True
        self.group_by_security_group = True
        self.group_by_tag = True
        self.include_powerstate = True

        self._inventory = dict(
            _meta=dict(
                hostvars=dict()
            ),
            azure=[]
        )

        self._get_settings()

        if self._args.resource_groups:
            self.resource_groups = self._args.resource_groups.split(',')

        if self._args.tags:
            self.tags = self._args.tags.split(',')

        if self._args.locations:
            self.locations = self._args.locations.split(',')

        if self._args.no_powerstate:
            self.include_powerstate = False

        self.get_inventory()
        print(self._json_format_dict(pretty=self._args.pretty))
        sys.exit(0)

    def _parse_cli_args(self):
        # Parse command line arguments
        parser = argparse.ArgumentParser(
            description='Produce an Ansible Inventory file for an Azure subscription')
        parser.add_argument('--list', action='store_true', default=True,
                            help='List instances (default: True)')
        parser.add_argument('--debug', action='store_true', default=False,
                            help='Send debug messages to STDOUT')
        parser.add_argument('--host', action='store',
                            help='Get all information about an instance')
        parser.add_argument('--pretty', action='store_true', default=False,
                            help='Pretty print JSON output(default: False)')
        parser.add_argument('--profile', action='store',
                            help='Azure profile contained in ~/.azure/credentials')
        parser.add_argument('--subscription_id', action='store',
                            help='Azure Subscription Id')
        parser.add_argument('--client_id', action='store',
                            help='Azure Client Id ')
        parser.add_argument('--secret', action='store',
                            help='Azure Client Secret')
        parser.add_argument('--tenant', action='store',
                            help='Azure Tenant Id')
        parser.add_argument('--ad_user', action='store',
                            help='Active Directory User')
        parser.add_argument('--password', action='store',
                            help='password')
        parser.add_argument('--cloud_environment', action='store',
                            help='Azure Cloud Environment name or metadata discovery URL')
        parser.add_argument('--resource-groups', action='store',
                            help='Return inventory for comma separated list of resource group names')
        parser.add_argument('--tags', action='store',
                            help='Return inventory for comma separated list of tag key:value pairs')
        parser.add_argument('--locations', action='store',
                            help='Return inventory for comma separated list of locations')
        parser.add_argument('--no-powerstate', action='store_true', default=False,
                            help='Do not include the power state of each virtual host')
        return parser.parse_args()

    def get_inventory(self):
        if len(self.resource_groups) > 0:
            # get VMs for requested resource groups
            for resource_group in self.resource_groups:
                try:
                    web_apps = self._webapp_client.web_apps.list_by_resource_group(resource_group)
                    app_service_plans = self._webapp_client.app_service_plans.list_by_resource_group(resource_group)
                except Exception as exc:
                    sys.exit("Error: fetching web applications for resource group {0} - {1}".format(resource_group, str(exc)))
                try:
                    redis_caches = self._redis_client.redis.list_by_resource_group(resource_group)
                except Exception as exc:
                    sys.exit("Error: fetching redis caches for resource group {0} - {1}".format(resource_group, str(exc)))
                try:
                    virtual_machines = self._compute_client.virtual_machines.list(resource_group)					
                except Exception as exc:
                    sys.exit("Error: fetching virtual machines for resource group {0} - {1}".format(resource_group, str(exc)))
                if self._args.host or self.tags:
                    selected_webapps = self._selected_webapps(web_apps)
                    selected_plans = self._selected_plans(app_service_plans)
                    selected_redis_cache = self._selected_redis_caches(redis_caches)
                    selected_machines = self._selected_machines(virtual_machines)
                    self._load_webapps(selected_webapps)
                    self._load_plans(selected_plans)
                    self._load_redis_caches(selected_redis_cache)
                    self._load_machines(selected_machines)
                else:
                    self._load_webapps(web_apps)
                    self._load_plans(app_service_plans)
                    self._load_redis_caches(redis_caches)
                    self._load_machines(virtual_machines)
        else:
            # get all webapps within the subscription
            try:
                web_apps = self._webapp_client.web_apps.list()
                app_service_plans = self._webapp_client.app_service_plans.list()
            except Exception as exc:
                sys.exit("Error: fetching virtual machines - {0}".format(str(exc)))
            # get all redis within the subscription
            try:
                redis_caches = self._redis_client.redis.list()
            except Exception as exc:
                sys.exit("Error: fetching redis caches - {0}".format(str(exc)))
            # get all VMs within the subscription
            try:
                virtual_machines = self._compute_client.virtual_machines.list_all()
            except Exception as exc:
                sys.exit("Error: fetching virtual machines - {0}".format(str(exc)))

            if self._args.host or self.tags or self.locations:
                selected_webapps = self._selected_webapps(web_apps)
                selected_plans = self._selected_plans(app_service_plans)
                selected_machines = self._selected_machines(virtual_machines)
                selected_redis_cache = self._selected_redis_caches(redis_caches)
                self._load_redis_caches(selected_redis_cache)
                self._load_machines(selected_machines)
                self._load_webapps(selected_webapps)
                self._load_plans(selected_plans)
            else:
                self._load_webapps(web_apps)
                self._load_plans(app_service_plans)
                self._load_machines(virtual_machines)
                self._load_redis_caches(redis_caches)

    def _load_redis_caches(self, redis_caches):
        for redis in redis_caches:
            id_dict = azure_id_to_dict(redis.id)

            # TODO - The API is returning an ID value containing resource group name in ALL CAPS. If/when it gets
            #       fixed, we should remove the .lower(). Opened Issue
            #       #574: https://github.com/Azure/azure-sdk-for-python/issues/574
            resource_group = id_dict['resourceGroups'].lower()

            #if self.group_by_security_group:
            #    self._get_security_groups(resource_group)

            redis_vars = dict(
                name = redis.name,
                type = redis.type,
                location = redis.location,
                resource_group = resource_group,
                enable_non_ssl_port = redis.enable_non_ssl_port,
                sku_name = redis.sku.name,
                sku_family = redis.sku.family,
                sku_capacity = redis.sku.capacity,
                provisioning_state = redis.provisioning_state                
            )

            self._add_redis(redis_vars)

    def _load_machines(self, machines):
        for machine in machines:
            id_dict = azure_id_to_dict(machine.id)

            # TODO - The API is returning an ID value containing resource group name in ALL CAPS. If/when it gets
            #       fixed, we should remove the .lower(). Opened Issue
            #       #574: https://github.com/Azure/azure-sdk-for-python/issues/574
            resource_group = id_dict['resourceGroups'].lower()

            if self.group_by_security_group:
                self._get_security_groups(resource_group)

            host_vars = dict(
                ansible_host=None,
                private_ip=None,
                private_ip_alloc_method=None,
                public_ip=None,
                public_ip_name=None,
                public_ip_id=None,
                public_ip_alloc_method=None,
                fqdn=None,
                location=machine.location,
                name=machine.name,
                type=machine.type,
                id=machine.id,
                tags=machine.tags,
                network_interface_id=None,
                network_interface=None,
                resource_group=resource_group,
                mac_address=None,
                plan=(machine.plan.name if machine.plan else None),
                virtual_machine_size=machine.hardware_profile.vm_size,
                computer_name=(machine.os_profile.computer_name if machine.os_profile else None),
                provisioning_state=machine.provisioning_state,
            )

            host_vars['os_disk'] = dict(
                name=machine.storage_profile.os_disk.name,
                operating_system_type=machine.storage_profile.os_disk.os_type.value
            )

            if self.include_powerstate:
                host_vars['powerstate'] = self._get_powerstate(resource_group, machine.name)

            if machine.storage_profile.image_reference:
                host_vars['image'] = dict(
                    offer=machine.storage_profile.image_reference.offer,
                    publisher=machine.storage_profile.image_reference.publisher,
                    sku=machine.storage_profile.image_reference.sku,
                    version=machine.storage_profile.image_reference.version
                )

            # Add windows details
            if machine.os_profile is not None and machine.os_profile.windows_configuration is not None:
                host_vars['windows_auto_updates_enabled'] = \
                    machine.os_profile.windows_configuration.enable_automatic_updates
                host_vars['windows_timezone'] = machine.os_profile.windows_configuration.time_zone
                host_vars['windows_rm'] = None
                if machine.os_profile.windows_configuration.win_rm is not None:
                    host_vars['windows_rm'] = dict(listeners=None)
                    if machine.os_profile.windows_configuration.win_rm.listeners is not None:
                        host_vars['windows_rm']['listeners'] = []
                        for listener in machine.os_profile.windows_configuration.win_rm.listeners:
                            host_vars['windows_rm']['listeners'].append(dict(protocol=listener.protocol,
                                                                             certificate_url=listener.certificate_url))

            for interface in machine.network_profile.network_interfaces:
                interface_reference = self._parse_ref_id(interface.id)
                network_interface = self._network_client.network_interfaces.get(
                    interface_reference['resourceGroups'],
                    interface_reference['networkInterfaces'])
                if network_interface.primary:
                    if self.group_by_security_group and \
                       self._security_groups[resource_group].get(network_interface.id, None):
                        host_vars['security_group'] = \
                            self._security_groups[resource_group][network_interface.id]['name']
                        host_vars['security_group_id'] = \
                            self._security_groups[resource_group][network_interface.id]['id']
                    host_vars['network_interface'] = network_interface.name
                    host_vars['network_interface_id'] = network_interface.id
                    host_vars['mac_address'] = network_interface.mac_address
                    for ip_config in network_interface.ip_configurations:
                        host_vars['private_ip'] = ip_config.private_ip_address
                        host_vars['private_ip_alloc_method'] = ip_config.private_ip_allocation_method
                        if ip_config.public_ip_address:
                            public_ip_reference = self._parse_ref_id(ip_config.public_ip_address.id)
                            public_ip_address = self._network_client.public_ip_addresses.get(
                                public_ip_reference['resourceGroups'],
                                public_ip_reference['publicIPAddresses'])
                            host_vars['ansible_host'] = public_ip_address.ip_address
                            host_vars['public_ip'] = public_ip_address.ip_address
                            host_vars['public_ip_name'] = public_ip_address.name
                            host_vars['public_ip_alloc_method'] = public_ip_address.public_ip_allocation_method
                            host_vars['public_ip_id'] = public_ip_address.id
                            if public_ip_address.dns_settings:
                                host_vars['fqdn'] = public_ip_address.dns_settings.fqdn

            self._add_host(host_vars)

    def _load_webapps(self, webapps):
        for webapp in webapps:
            id_dict = azure_id_to_dict(webapp.id)

            resource_group = id_dict['resourceGroups'].lower()

            if self.group_by_security_group:
                self._get_security_groups(resource_group)

            host_vars = dict(
                ansible_host=None,
                private_ip=None,
                private_ip_alloc_method=None,
                public_ip=None,
                public_ip_name=None,
                public_ip_id=None,
                public_ip_alloc_method=None,
                fqdn=webapp.default_host_name,
                location=webapp.location,
                name=webapp.name,
                type=webapp.type,
                id=webapp.id,
                tags=webapp.tags,
                network_interface_id=None,
                network_interface=None,
                resource_group=resource_group,
                mac_address=None,
                plan=webapp.server_farm_id,
                virtual_machine_size=None,
                computer_name=None,
                provisioning_state=webapp.state,
            )

            if self.include_powerstate:
                host_vars['powerstate'] = webapp.enabled

            host_vars['type'] = "web_app"        

            self._add_host(host_vars)

    def _load_plans(self, plans):
        for plan in plans:
            id_dict = azure_id_to_dict(plan.id)

            resource_group = id_dict['resourceGroups'].lower()

            if self.group_by_security_group:
                self._get_security_groups(resource_group)

            host_vars = dict(
                ansible_host=None,
                private_ip=None,
                private_ip_alloc_method=None,
                public_ip=None,
                public_ip_name=None,
                public_ip_id=None,
                public_ip_alloc_method=None,
                fqdn=None,
                location=plan.location,
                name=plan.name,
                type=plan.type,
                id=plan.id,
                tags=plan.tags,
                network_interface_id=None,
                network_interface=None,
                resource_group=resource_group,
                mac_address=None,
                plan=None,
                virtual_machine_size=None,
                computer_name=None,
                provisioning_state=plan.provisioning_state
            )

            host_vars['sku'] = dict(
                name=plan.sku.name,
                tier=plan.sku.tier,
                size=plan.sku.size,
                family=plan.sku.family,
                capacity=plan.sku.capacity
            )

            if self.include_powerstate:
                host_vars['powerstate'] = True

            host_vars['type'] = "app_service_plan"    

            self._add_host(host_vars)

    def _selected_machines(self, virtual_machines):
        selected_machines = []
        for machine in virtual_machines:
            if self._args.host and self._args.host == machine.name:
                selected_machines.append(machine)
            if self.tags and self._tags_match(machine.tags, self.tags):
                selected_machines.append(machine)
            if self.locations and machine.location in self.locations:
                selected_machines.append(machine)
        return selected_machines
	
    def _selected_redis_caches(self, redis_caches):
        selected_redis_caches = []
        for redis_cache in redis_caches:
            if self._args.host_name and self._args.host_name == redis_cache.host_name:
                selected_redis_caches.append(redis_cache)
            if self.tags and self._tags_match(machine.tags, self.tags):
                selected_redis_caches.append(redis_cache)
            if self.locations and machine.location in self.locations:
                selected_redis_caches.append(redis_cache)
        return selected_redis_caches

    def _selected_webapps(self, webapps):
        selected_webapps = []
        for webapp in webapps:
            if self._args.host and self._args.host == webapp.name:
                selected_webapps.append(webapp)
            if self.tags and self._tags_match(webapp.tags, self.tags):
                selected_webapps.append(webapp)
            if self.locations and webapp.location in self.locations:
                selected_webapps.append(webapp)
        return selected_webapps

    def _selected_plans(self, plans):
        selected_plans = []
        for plan in plans:
            if self._args.host and self._args.host == plan.name:
                selected_plans.append(plan)
            if self.tags and self._tags_match(plan.tags, self.tags):
                selected_plans.append(plan)
            if self.locations and plan.location in self.locations:
                selected_plans.append(plan)
        return selected_plans        

    def _get_security_groups(self, resource_group):
        ''' For a given resource_group build a mapping of network_interface.id to security_group name '''
        if not self._security_groups:
            self._security_groups = dict()
        if not self._security_groups.get(resource_group):
            self._security_groups[resource_group] = dict()
            for group in self._network_client.network_security_groups.list(resource_group):
                if group.network_interfaces:
                    for interface in group.network_interfaces:
                        self._security_groups[resource_group][interface.id] = dict(
                            name=group.name,
                            id=group.id
                        )

    def _add_redis(self, vars):

        redis_name = self._to_safe(vars['name'])
        resource_group = self._to_safe(vars['resource_group'])

        if self.group_by_resource_group:
            if not self._inventory.get(resource_group):
                self._inventory[resource_group] = []
            self._inventory[resource_group].append(redis_name)

        self._inventory['_meta']['hostvars'][redis_name] = vars
        self._inventory['azure'].append(redis_name)

    def _add_host(self, vars):

        host_name = self._to_safe(vars['name'])
        resource_group = self._to_safe(vars['resource_group'])
        type_info = self._to_safe(vars['type'])
        security_group = None
        if vars.get('security_group'):
            security_group = self._to_safe(vars['security_group'])

        if self.group_by_resource_group:
            if not self._inventory.get(resource_group):
                self._inventory[resource_group] = []
            self._inventory[resource_group].append(host_name)

        if not self._inventory.get(type_info):
            self._inventory[type_info] = []
        self._inventory[type_info].append(host_name)    

        if self.group_by_location:
            if not self._inventory.get(vars['location']):
                self._inventory[vars['location']] = []
            self._inventory[vars['location']].append(host_name)

        if self.group_by_security_group and security_group:
            if not self._inventory.get(security_group):
                self._inventory[security_group] = []
            self._inventory[security_group].append(host_name)

        self._inventory['_meta']['hostvars'][host_name] = vars
        self._inventory['azure'].append(host_name)

        if self.group_by_tag and vars.get('tags'):
            for key, value in vars['tags'].items():
                safe_value = self._to_safe(value)
                if not self._inventory.get(safe_value):
                    self._inventory[safe_value] = []
                self._inventory[safe_value].append(host_name)

    def _json_format_dict(self, pretty=False):
        # convert inventory to json
        if pretty:
            return json.dumps(self._inventory, sort_keys=True, indent=2)
        else:
            return json.dumps(self._inventory)

    def _get_settings(self):
        # Load settings from the .ini, if it exists. Otherwise,
        # look for environment values.
        file_settings = self._load_settings()
        if file_settings:
            for key in AZURE_CONFIG_SETTINGS:
                if key in ('resource_groups', 'tags', 'locations') and file_settings.get(key):
                    values = file_settings.get(key).split(',')
                    if len(values) > 0:
                        setattr(self, key, values)
                elif file_settings.get(key):
                    val = self._to_boolean(file_settings[key])
                    setattr(self, key, val)
        else:
            env_settings = self._get_env_settings()
            for key in AZURE_CONFIG_SETTINGS:
                if key in('resource_groups', 'tags', 'locations') and env_settings.get(key):
                    values = env_settings.get(key).split(',')
                    if len(values) > 0:
                        setattr(self, key, values)
                elif env_settings.get(key, None) is not None:
                    val = self._to_boolean(env_settings[key])
                    setattr(self, key, val)

    def _parse_ref_id(self, reference):
        response = {}
        keys = reference.strip('/').split('/')
        for index in range(len(keys)):
            if index < len(keys) - 1 and index % 2 == 0:
                response[keys[index]] = keys[index + 1]
        return response

    def _to_boolean(self, value):
        if value in ['Yes', 'yes', 1, 'True', 'true', True]:
            result = True
        elif value in ['No', 'no', 0, 'False', 'false', False]:
            result = False
        else:
            result = True
        return result

    def _get_env_settings(self):
        env_settings = dict()
        for attribute, env_variable in AZURE_CONFIG_SETTINGS.items():
            env_settings[attribute] = os.environ.get(env_variable, None)
        return env_settings

    def _load_settings(self):
        basename = os.path.splitext(os.path.basename(__file__))[0]
        default_path = os.path.join(os.path.dirname(__file__), (basename + '.ini'))
        path = os.path.expanduser(os.path.expandvars(os.environ.get('AZURE_INI_PATH', default_path)))
        config = None
        settings = None
        try:
            config = cp.ConfigParser()
            config.read(path)
        except:
            pass

        if config is not None:
            settings = dict()
            for key in AZURE_CONFIG_SETTINGS:
                try:
                    settings[key] = config.get('azure', key, raw=True)
                except:
                    pass

        return settings

    def _tags_match(self, tag_obj, tag_args):

        if not tag_obj:
            return False

        matches = 0
        for arg in tag_args:
            arg_key = arg
            arg_value = None
            if re.search(r':', arg):
                arg_key, arg_value = arg.split(':')
            if arg_value and tag_obj.get(arg_key, None) == arg_value:
                matches += 1
            elif not arg_value and tag_obj.get(arg_key, None) is not None:
                matches += 1
        if matches == len(tag_args):
            return True
        return False

    def _to_safe(self, word):
        ''' Converts 'bad' characters in a string to underscores so they can be used as Ansible groups '''
        regex = r"[^A-Za-z0-9\_"
        if not self.replace_dash_in_groups:
            regex += r"\-"
        return re.sub(regex + "]", "_", word)


def main():
    if not HAS_AZURE:
        sys.exit("The Azure python sdk is not installed (try `pip install 'azure>={0}' --upgrade`) - {1}".format(AZURE_MIN_VERSION, HAS_AZURE_EXC))

    AzureInventory()

main()
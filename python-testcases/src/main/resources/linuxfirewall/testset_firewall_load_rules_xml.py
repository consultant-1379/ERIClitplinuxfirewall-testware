"""
COPYRIGHT Ericsson 2019
The copyright to the computer program(s) herein is the property of
Ericsson Inc. The programs may be used and/or copied only with written
permission from Ericsson Inc. or in accordance with the terms and
conditions stipulated in the agreement/contract under which the
program(s) have been supplied.

@since:     May 2014, refactored Dec 2015, Apr 2016, Jan 2018
@author:    Priyanka/Maria; Maurizio, Terry; John Kelly
@summary:   LITPCDS-2076
                As a LITP User, I want to remove/update extra firewall
                rules to an already applied configuration, so that I can
                enhance or modify my firewall configuration
"""
import test_constants as const
from litp_generic_test import GenericTest, attr
import firewall_test_data
import os


class FirewallLoadRulesXML(GenericTest):
    """
    As a LITP User, I want to create,remove and update a list of
    IPv4 or IPv6 firewall rules that can be applied to any node,
    so that I can benefit from the increased security.
    """

    def setUp(self):
        """ Runs before every single test """
        super(FirewallLoadRulesXML, self).setUp()

        self.ms_node = self.get_management_node_filename()
        self.clusters_path = self.find(
            self.ms_node, '/deployments', 'vcs-cluster')[0]
        self.nodes_paths = self.find(
            self.ms_node, self.clusters_path, "node")
        self.ms_path = ['/ms']

        # Must have at least 2 nodes
        self.assertTrue(len(self.nodes_paths) >= 2,
                        'System has less than 2 nodes')

        self.ip_tables = [const.IPTABLES_PATH, const.IP6TABLES_PATH]

    def tearDown(self):
        """ Runs after every single test """
        super(FirewallLoadRulesXML, self).tearDown()

    def _get_path_config(self, system_paths, systems_type):
        """
        Description:
            Returns system information about the firewall configuration.
            Retrieves the name of the system, the configure path of the system
            and the firewall configuration path as well as setting the backup
            and import file locations.
        Args:
            system_paths (list): List of paths of nodes or clusters you want
                to find the firewall configuration paths on.
                NOTE: All paths must be of the same system type.
            systems_type (str): Type of system - 'node' or 'cluster'.
        Returns:
            systems_info (list): List of dictionaries with information
                about the system.
                e.g. [{'path': '/deployments/d1/clusters/c1',
                    'name': 'c1',
                    'type': 'cluster',
                    'system_config': '/deployments/d1/clusters/c1/configs',
                    'fw_config':
                        '/deployments/d1/clusters/c1/configs/fw_config_init',
                    'backup_file': '/tmp/xml_cluster_config_story2076.xml',
                    'import_file': '/tmp/xml_cluster_fw_rules_story2076.xml'
                }]
        """
        systems_info = []
        for path in system_paths:
            system_info = {}

            # Node path
            system_info['path'] = path

            if systems_type == 'node':
                system_info['name'] = self.get_hostname_of_node(
                    self.ms_node, path)
            else:
                system_info['name'] = path.split('/')[-1]

            system_info['type'] = systems_type

            self.log('info', 'Finding {0} configuration path'.format(
                system_info['name']))

            system_info['system_config'] = self.find(
                self.ms_node, path, "collection-of-{0}-config".format(
                    systems_type))[0]

            self.log('info', 'Finding {0} firewall config path'.format(
                system_info['name']))

            system_info['fw_config'] = self.find(
                self.ms_node, system_info['system_config'],
                "firewall-{0}-config".format(systems_type))[0]

            # Backup file
            system_info['backup_file'] = "/tmp/xml_{0}_config_" \
                "story2076.xml".format(system_info['name'])

            # Path to importing firewall rules file
            system_info['import_file'] = "/tmp/xml_{0}_fw_rules_" \
                "story2076.xml".format(systems_type)

            systems_info.append(system_info)
        return systems_info

    def _get_iptables_dict(self, node, args='-S'):
        """
        Description:
            Returns dictionary of iptables and ip6tables entries on given node.
        Args:
            node (str): Node to get ip(6)tables rules.
        Kwargs:
            args (str): Arguments for the ip(6)tables commands. Default is '-S'
        Returns:
            iptables (dict): dictionary containing iptables/ip6tables
        """
        iptables = {}

        for ip_version in self.ip_tables:
            is_ipv6 = ip_version == const.IP6TABLES_PATH

            iptables[ip_version] = self.get_iptables_configuration(
                node, args=args, ipv6=is_ipv6)

        return iptables

    def _check_empty_iptables(self, node, check_list=None,
                              expect_positive=True):
        """
        Description:
            Asserts iptables & ip6tables on given node are
            empty or asserts that they are not empty.
        Args:
            node (str): Node to check ip(6)tables
        Kwargs:
            check_list (dict): Results from _get_iptables_dict().
                Default is None. If None, then it'll run command to
                retrieve the iptables
            expect_positive (bool): Expect positive outcome. Default is True
        """
        if check_list:
            current_tables = check_list
        else:
            current_tables = self._get_iptables_dict(node)

        for ip_version in current_tables:
            if expect_positive:
                self.assertEqual(current_tables[ip_version][3:], [],
                                 "{0} {1} is not empty".format(
                                     node, ip_version.split('/')[-1]))
            else:
                self.assertNotEqual(current_tables[ip_version][3:], [],
                                    "{0} {1} is unexpectedly empty".format(
                                        node, ip_version.split('/')[-1]))

    def _create_fw_rule_item(self, fw_config_url, item_id, props):
        """
        Description:
            Creates a firewall item at the specified
            URL with the given path ID and props.
        Args:
            fw_config_url (str): Firewall configuration item url
            item_id (str): Firewall rule item ID
            props (str): Firewall rule options
        """
        firewall_rule = '{0}/rules/{1}'.format(fw_config_url, item_id)
        self.execute_cli_create_cmd(
            self.ms_node, firewall_rule, "firewall-rule", props)

    @attr('all', 'revert', 'story2076', 'story2076_tc05')
    def test_01_p_load_rules_from_XML(self):
        """
        @tms_id: litpcds_2076_tc20
        @tms_requirements_id: LITPCDS-2076
        @tms_title: Import, update and remove firewall rules via XML and CLI
        @tms_description: Test XML exporting, importing, deletion and loading
            of firewall rules on nodes, cluster and MS level are applied in
            iptables/ip6tables.
        @tms_test_steps:
            @step: Export existing cluster and node firewall config
            @result: Items are exported successfully to files
            @step: Save current iptables/ip6tables configuration
            @result: Current iptables/ip6tables configuration saved
            @step: Copy test XML files to MS node
            @result: Test XML files copied to MS
            @step: Load test XML files with test firewall rules
            @result: Test XML files loaded successfully in LITP
            @step: Create and run plan
            @result: Plan successful
            @step: Check if new firewall rules are present on the nodes
            @result: Firewall rules present
            @step: Remove firewall configuration from one of the nodes,
                create/run plan
            @result: Plan successful
            @step: Check node-level rules have been removed from that node and
                cluster-level firewall rules are still present
            @result: Node-level rules no longer on node and cluster-level
                firewall rules are still applied to that node
            @step: Remove cluster firewall configuration item, create/run plan
            @result: Plan successful
            @step: Check if cluster firewall rules are removed from nodes
            @result: Cluster-level firewall rules removed from nodes
            @step: Remove other node and MS firewall configuration items,
                create firewall rule on cluster, create/run plan
            @result: Plan successful
            @step: Check node-level rules have been removed from other node,
                MS rules have been removed, and cluster firewall rule is
                present on nodes
            @result: Rules as expected
            @step: Restore cluster firewall configuration, create/run plan
            @result: Plan successful, cluster level firewall rules present
                on nodes
            @step: Restore firewall configuration on nodes and MS, create/run
                plan
            @result: Plan successful, firewall rules applied to nodes and MS
        @tms_test_precondition: N/A
        @tms_execution_type: Automated
        """
        ms_info = self._get_path_config(self.ms_path, 'node')
        cluster_info = self._get_path_config(
            [self.clusters_path], 'cluster')
        nodes_info = self._get_path_config(
            self.nodes_paths[:2], 'node')

        self.log('info', '1. Export existing cluster and node firewall config')
        self.log('info', '2. Save current iptables/ip6tables configuration.')

        for node in nodes_info + ms_info:
            node['default_iptables'] = self._get_iptables_dict(node['name'])

        for system in cluster_info + nodes_info + ms_info:
            self.execute_cli_export_cmd(
                self.ms_node, system['fw_config'], system['backup_file'])

        self.log('info', '3. Copy XML files to MS node.')
        xml_filenames = ['xml_cluster_fw_rules_story2076.xml',
                         'xml_node_fw_rules_story2076.xml']

        local_filepath = os.path.dirname(__file__)

        for xml_filename in xml_filenames:
            local_xml_filepath = local_filepath + "/xml_files/" + xml_filename
            xml_filepath = "/tmp/" + xml_filename

            self.assertTrue(self.copy_file_to(self.ms_node, local_xml_filepath,
                                              xml_filepath, root_copy=True))

        self.log('info', "4. Merge test XML's into current firewall rules.")
        for system in nodes_info + cluster_info + ms_info:
            self.execute_cli_load_cmd(
                self.ms_node, system['fw_config'],
                system['import_file'], "--merge")

        self.log('info', '5. Create and run plan to implement XML changes.')
        self.run_and_check_plan(
            self.ms_node, const.PLAN_COMPLETE, plan_timeout_mins=5)

        self.log('info', '6. Check new firewall rules are applied to nodes.')
        self.check_iptables(ms_info[0]['name'],
                            firewall_test_data.XML_NODE_RULES)

        for node in nodes_info:
            expected_updated_iptables = firewall_test_data.XML_NODE_RULES + \
                firewall_test_data.XML_CLUSTER_RULES_DEFAULT

            node['updated_iptables'] = self._get_iptables_dict(node['name'])

            self.check_iptables(node['name'], expected_updated_iptables,
                check_list=node['updated_iptables'][const.IPTABLES_PATH])

            self.check_iptables(node['name'],
                                firewall_test_data.XML_CLUSTER_RULES_NAT,
                                args='-S --table nat')

        self.log('info', '7. Remove {0} firewall configuration.'.format(
            nodes_info[0]['name']))
        self.execute_cli_remove_cmd(self.ms_node, nodes_info[0]['fw_config'])

        self.log('info', '8. Create and run plan to implement removal of '
            '{0} firewall configuration'.format(nodes_info[0]['name']))
        self.run_and_check_plan(
            self.ms_node, const.PLAN_COMPLETE, plan_timeout_mins=5)

        self.log('info', '9. Check if cluster firewall config is still '
                         'applied to {0}.'.format(nodes_info[0]['name']))
        updated_iptables = self._get_iptables_dict(nodes_info[0]['name'])

        self._check_empty_iptables(
            nodes_info[0]['name'], check_list=updated_iptables,
            expect_positive=False)
        for ip_version in updated_iptables:
            self.assertNotEqual(updated_iptables[ip_version],
                                nodes_info[0]['updated_iptables'],
                                'No rules have been removed from '
                                '{0}'.format(nodes_info[0]['name']))

        self.log('info', '10. Remove cluster firewall configuration item.')
        self.execute_cli_remove_cmd(self.ms_node, cluster_info[0]['fw_config'])

        self.log('info', '11. Create and run plan to remove '
                         'cluster firewall configuration item')
        self.run_and_check_plan(
            self.ms_node, const.PLAN_COMPLETE, plan_timeout_mins=5)

        self.log('info', '12. Check if cluster firewall rules '
                         'have been removed from nodes.')
        self._check_empty_iptables(nodes_info[0]['name'])

        self.assertNotEqual(nodes_info[1]['default_iptables'],
                            nodes_info[1]['updated_iptables'],
                            "Cluster firewall rules haven't been removed "
                            "from {0} correctly".format(nodes_info[1]['name']))

        for node in nodes_info:
            del node['updated_iptables']

        self.log('info', '13. Remove node firewall configuration item from '
                         '{0} and MS.'.format(nodes_info[1]['name']))
        for node in [nodes_info[1]] + ms_info:
            self.execute_cli_remove_cmd(self.ms_node, node['fw_config'])

        self.log('info', '14. Create firewall rule on cluster.')
        props = 'name="099 icmpv6" proto="ipv6-icmp" provider="ip6tables"'
        self.execute_cli_create_cmd(
            self.ms_node, cluster_info[0]['fw_config'],
            'firewall-cluster-config', add_to_cleanup=False)

        self._create_fw_rule_item(
            cluster_info[0]['fw_config'], "fw_icmpv6", props)

        self.log('info', '15. Create and run plan to implement the removal of '
                         'nodes and MS firewall config and creation of '
                         'cluster firewall rule.')

        self.run_and_check_plan(self.ms_node,
                                const.PLAN_COMPLETE, plan_timeout_mins=5)

        iptables_config = set(self.get_iptables_configuration(self.ms_node))
        ip6tables_config = set(self.get_iptables_configuration(
            self.ms_node, ipv6=True))

        default_iptables = set([
            "-P INPUT ACCEPT",
            "-P FORWARD ACCEPT",
            "-P OUTPUT ACCEPT"
        ])

        self.assertTrue(default_iptables == iptables_config,
                        "All rules not removed in ip4")
        self.assertTrue(default_iptables == ip6tables_config,
                        "All rules not removed in ip6")

        self.log('info', '16. Check if cluster rule has been applied to nodes')
        rules = [['ipv6-icmp', '099 icmpv6 ipv6']]
        for node in nodes_info:
            node['updated_iptables'] = self._get_iptables_dict(node['name'])
            self.check_iptables(
                node['name'], rules,
                check_list=node['updated_iptables'][const.IP6TABLES_PATH])

        self.log('info', '17. Restore cluster firewall configuration.')
        self.execute_cli_load_cmd(
            self.ms_node, cluster_info[0]['system_config'],
            cluster_info[0]['backup_file'], '--replace')

        self.log('info', '18. Create and run plan to implement '
                         'restore of cluster firewall configuration.')
        self.run_and_check_plan(
            self.ms_node, const.PLAN_COMPLETE, plan_timeout_mins=5)

        self.log('info', '19. Check if cluster firewall config '
                         'has been applied to nodes.')
        for node in nodes_info:
            updated_iptables = self._get_iptables_dict(node['name'])

            self.assertNotEqual(node['updated_iptables'],
                                updated_iptables,
                                "Cluster firewall rules haven't been applied "
                                "to {0} correctly".format(node['name']))

            self._check_empty_iptables(
                node['name'], check_list=updated_iptables,
                expect_positive=False)

        self.log('info', '20. Restore firewall configuration on all nodes.')
        for node in nodes_info + ms_info:
            self.execute_cli_load_cmd(
                self.ms_node, node['system_config'],
                node['backup_file'], '--replace')

        self.log('info', '21. Create and run plan to implement restore '
                         'of all nodes firewall configuration')
        self.run_and_check_plan(
            self.ms_node, const.PLAN_COMPLETE, plan_timeout_mins=5)

        self.log('info', '22. Check firewall config has'
                         ' been applied correctly.')
        for node in nodes_info + ms_info:
            updated_iptables = self._get_iptables_dict(node['name'])

            self.assertEqual(node['default_iptables'], updated_iptables,
                             'Firewall configuration did not reset to default'
                             ' on {0}'.format(node['name']))

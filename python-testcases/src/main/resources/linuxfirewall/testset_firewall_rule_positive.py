"""
COPYRIGHT Ericsson 2019
The copyright to the computer program(s) herein is the property of
Ericsson Inc. The programs may be used and/or copied only with written
permission from Ericsson Inc. or in accordance with the terms and
conditions stipulated in the agreement/contract under which the
program(s) have been supplied.

@since:     Jan 2018
@author:    Aisling Stafford, John Kelly
@summary:   LITPCDS-2075
                As a LITP User, I want to create a list of IPv4 or
                IPv6 firewall rules that can be applied to any node, so that
                I can benefit from the increased security
            LITPCDS-2076
                As a LITP User, I want to remove/update extra firewall rules to
                an already applied configuration, so that I can enhance
                or modify my firewall configuration
            LITPCDS-2892
                As an application designer I want MCollective to use SSL so
                that broadcasting to nodes is more secure
            TORF-217079
                As a LITP user I want to be able to accept/block
                specific types of ICMPv4 & ICMPv6 packets in my
                firewalls configuration (DTAG Item 12)
            TORF-199859
                Add additional SNAT firewall properties to LITP model
            LITPCDS-214216
                As a LITP user I want to be able to configure a firewall rule
                with a single source or destination port specified and not have
                '-m multiports' included in the corresponding
                iptables/ip6tables rule that is configured.
            TORF-200553
                Add to the firewall-rule item-type new properties "algo"
                and "string" and update the existing "source" property
                to support the "!" character
"""
import test_constants as const
from litp_generic_test import GenericTest, attr
import firewall_test_data


class FirewallRulePositive(GenericTest):
    """
     As a LITP User, I want to create/update a list of IPv4 and IPv6 firewall
     rules that can be applied to any node, so that I can benefit from
     the increased security
    """
    def setUp(self):
        """ Runs before every single test """
        super(FirewallRulePositive, self).setUp()
        self.ms_node = self.get_management_node_filename()
        self.peer_nodes = self.get_managed_node_filenames()
        self.cluster_fw_rules_lst = firewall_test_data.CLUSTER_RULES_LIST
        self.node_ms_fw_rules_lst = firewall_test_data.NODE_MS_RULES_LIST
        self.update_fw_rules_lst = firewall_test_data.UPDATE_FW_RULES_LIST
        self.ip_tables = [const.IPTABLES_PATH, const.IP6TABLES_PATH]
        self.rules_ms = firewall_test_data.RULES_MS
        self.rules_node = firewall_test_data.RULES_NODE
        self.updated_rules_ms = firewall_test_data.UPDATED_RULES_MS
        self.updated_rules_node = firewall_test_data.UPDATED_RULES_NODE
        self.drop_all_rule_false = firewall_test_data.\
            FIRST_UPDATE_FW_RULE_DISABLE_NODE
        self.drop_all_rule_true = firewall_test_data.\
            SECOND_UPDATE_FW_RULE_DISABLE_NODE

        # Firewall Rules path under Node
        node_url = self.find(self.ms_node, '/deployments', 'node')

        self.node_config_path = self.find(
            self.ms_node, node_url[0], "firewall-node-config")[0]

        self.fw_rules_n1_path = '{0}/rules'.format(
                self.find(self.ms_node, node_url[0],
                          'firewall-node-config')[0])

        self.fw_rules_n2_path = '{0}/rules'.format(
                self.find(self.ms_node, node_url[1],
                          'firewall-node-config')[0])

        # Firewall Rules path under Deployment
        cluster_path_url = self.find(self.ms_node, '/deployments',
                                     'vcs-cluster')[0]
        self.cluster_configs_path = self.find(
            self.ms_node, cluster_path_url, 'collection-of-cluster-config')[0]
        self.cluster_rules_parent_path = self.find(
            self.ms_node, self.cluster_configs_path,
            'collection-of-firewall-rule')[0]
        # Firewall Rules path under MS
        self.ms_rules_parent_path = self.find(self.ms_node, '/ms',
                                              'collection-of-firewall-rule')[0]

    def tearDown(self):
        """ Runs after every single test """
        super(FirewallRulePositive, self).tearDown()

    def get_rule_parent_path(self, fw_type):
        """
        Description:
            Determines parent path the given firewall rule
            is to be added under, i.e. MS, node, cluster

        Args:
            fw_type (str): Type of rule
                    i.e. "ms", "cluster", "node", "node-config"

        Returns:
            str. Parent path of the firewall rule
        """
        if fw_type == "ms":
            return self.ms_rules_parent_path
        elif fw_type == "cluster":
            return self.cluster_rules_parent_path
        elif fw_type == "node-config":
            return self.node_config_path
        else:
            return self.fw_rules_n1_path

    def create_update_fw_rule(self, fw_dict, update=False, cleanup=True):
        """
        Description:
            Creates/updates LITP firewall rule with the given properties

        Args:
            fw_dict (dict): List of dictionaries containing information
                        about rule to create/update
                        i.e Type (node, cluster, ms rule), path name,
                        rule properties

        Kwargs:
            update (boolean): Set to True if you want to update existing item
                          in the given dictionary, False if you want to
                          create the item. Default is False.

            cleanup (boolean): Set to False if you want to keep created
                           items/updates in the LITP model after the
                           test has completed, True if you want them
                           removed during test cleanup. Default is True.
        """
        fw_rule_path = self.get_rule_parent_path(fw_dict["TYPE"])

        for index, path_name in enumerate(fw_dict["PATH_NAME"]):
            if fw_rule_path == self.node_config_path:
                fw_path = fw_rule_path
            else:
                fw_path = "{0}/{1}".format(fw_rule_path, path_name)

            fw_props = ""
            for prop_name, prop_value in fw_dict["PROPS"][index].iteritems():
                if prop_name == prop_value:
                    fw_props += '{0} '.format(prop_value)
                else:
                    fw_props += '{0}="{1}" '.format(prop_name, prop_value)

            delete = False
            if not update:
                self.execute_cli_create_cmd(self.ms_node, fw_path,
                                            'firewall-rule', fw_props,
                                            add_to_cleanup=cleanup)
                if fw_dict["TYPE"] == "node":
                    self.execute_cli_create_cmd(self.ms_node,
                                                fw_path.replace(
                                                    self.fw_rules_n1_path,
                                                    self.fw_rules_n2_path),
                                                'firewall-rule', fw_props,
                                                add_to_cleanup=cleanup)
            else:
                if fw_dict["DELETE_PROP"] == [index]:
                    delete = True

                self.execute_cli_update_cmd(self.ms_node, fw_path, fw_props,
                                            action_del=delete)

                if fw_dict["TYPE"] == "node":
                    self.execute_cli_update_cmd(self.ms_node,
                                                fw_path.replace(
                                                    self.fw_rules_n1_path,
                                                    self.fw_rules_n2_path),
                                                fw_props,
                                                action_del=delete)

    def check_rules_applied(self, nodes, rules_ms,
                            rules_node, expect_present=True):
        """
        Description:
            Checks given rules are applied on MS and specified node.

        Args:
            nodes (lst): Peer node(s) to check iptables. MS node
                        will also be checked.

            ms_rules_dict (dict): Dictionary of tables containing dictionary of
                              ipv4 and ipv6 rules on the MS
                              i.e. {'filter': {iptables: ['INPUT', '21 test1'],
                                   ['FORWARD', '134 test2']},
                                   ip6tables: ['INPUT', '231 test3']}}

            node_rules_dict (dict): Dictionary of tables with each containing a
                                dictionary with ipv4 and ipv6 rules on nodes
                                i.e. {'mangle':
                                    {iptables: ['INPUT', '021 test1'],
                                            ['FORWARD', '134 test2']},
                                      ip6tables: ['INPUT', '231 test3']}}
        Kwargs:
            expect_present (bool): If set to False, will expect rules
                        passed in to not be in ip(6)tables. Default is True.
        """
        self.log('info', 'Checking rules on the MS...')
        for table in rules_ms:
            for iptable in rules_ms[table]:
                if rules_ms[table][iptable] == []:

                    self.log('info', 'No {0} rules were created/updated '
                             'on table {1} for the MS'.format(iptable, table))
                    continue

                ipv6 = False
                if iptable == "ip6tables":
                    ipv6 = True

                self.log('info', 'Checking MS {0} rules on '
                                 'table {1}'.format(iptable, table))

                self.check_iptables(self.ms_node, rules_ms[table][iptable],
                                    args='-S --table {0}'.format(table),
                                    ipv6=ipv6, expect_present=expect_present)

        self.log('info', 'Checking rules on peer nodes...')
        for table in rules_node:
            for iptable in rules_node[table]:
                ipv6 = False
                if iptable == "ip6tables":
                    ipv6 = True

                self.log('info', 'Checking nodes {0} rules '
                                 'on table {1}'.format(iptable, table))

                if not isinstance(nodes, list):
                    nodes = [nodes]

                for node in nodes:
                    if rules_node[table][iptable] == []:
                        self.log('info', 'No {0} rules were created/updated '
                                 'on table {1} for node "{2}".'.format(
                            iptable, table, node))
                        continue

                    self.check_iptables(node,
                                        rules_node[table][iptable],
                                        args='-S --table {0}'.format(table),
                                        ipv6=ipv6,
                                        expect_present=expect_present)

    def check_rules_in_model(self, rules_lst):
        """
        Description:
            Returns True if all given rules are present in LITP model and have
            state 'Applied', or False if none of the rules are in the model.
            Raises AssertionError if only a subset of the rules are present or
            if any rule is not in state 'Applied'.

        Args:
            rules_lst (list): List of dictionaries containing
                        information about given rules
                        i.e. Type (node, cluster, ms rule), path name,
                        rule properties

        Returns:
            bool. True if rules are present in LITP model
                and in Applied state, or False if not present.
        """
        rules_present = set()
        for rule in rules_lst:
            parent_path = self.get_rule_parent_path(rule["TYPE"])

            for rule_path_name in rule["PATH_NAME"]:
                fw_path = "{0}/{1}".format(parent_path, rule_path_name)
                item_found = self.find(self.ms_node, fw_path,
                                       'firewall-rule', assert_not_empty=False)
                if item_found:
                    state = self.get_item_state(self.ms_node, fw_path)
                    self.assertEqual("Applied", state)
                    rules_present.add(True)
                else:
                    rules_present.add(False)

                if rule["TYPE"] == "node":
                    fw_path = "{0}/{1}".format(self.fw_rules_n2_path,
                                               rule_path_name)
                    item_found = self.find(self.ms_node, fw_path,
                                           'firewall-rule',
                                           assert_not_empty=False)
                    if item_found:
                        state = self.get_item_state(self.ms_node, fw_path)
                        self.assertEqual("Applied", state)
                        rules_present.add(True)
                    else:
                        rules_present.add(False)

            self.assertTrue(len(rules_present) == 1,
                            "LITP model not in expected tate for test")

        return rules_present.pop()

    def _check_ports(self, node, iptables, ports, expect_present=True):
        """
        Description:
            Checks firewall ports on a given node.
        Args:
            node (str): Node you wish to check the ports on
            iptables (list): Results from the ip(6)tables command
            ports (list): List of ports to check
        Kwargs:
            expect_present (bool): If port should be present. Default is True.
        """
        rules = []

        for port in ports:
            rules.append(['dport', port])

        self.check_iptables(node, rules, check_list=iptables,
                            expect_present=expect_present)

    @attr('all', 'revert', 'story2076', 'story2076_tc04')
    def test_01_p_default_ports(self):
        """
        @tms_id: litpcds_2892_tc28
        @tms_requirements_id: LITPCDS-2076, LITPCDS-2892
        @tms_title: Firewall config creates default rules
        @tms_description: Verify that correct set of
            ports are open and closed by default
        @tms_test_steps:
            @step: Check iptables & ip6tables on MS
                contain correct rules for ports
            @result: MS iptables & ip6tables contain correct
                rules and correct ports are opened/closed
            @step: Check iptables & ip6tables on peer
                nodes contain correct rules for ports
            @result: iptables & ip6tables on peer nodes contain
                correct rules and correct ports are opened/closed
        @tms_test_precondition: N/A
        @tms_execution_type: Automated
        """
        for ip_version in self.ip_tables:
            is_ipv6 = ip_version == const.IP6TABLES_PATH

            ms_iptables = self.get_iptables_configuration(
                self.ms_node, ipv6=is_ipv6)

            self.log('info', '1. Checking if correct ports are open on MS')
            self._check_ports(self.ms_node, ms_iptables,
                              firewall_test_data.DEFAULT_MS_IP4_6_PORTS)

            self.log('info', '2. Checking if correct ports are closed on MS')
            self._check_ports(self.ms_node, ms_iptables,
                              firewall_test_data.DEFAULT_MS_CLOSED_PORTS,
                              False)

            for node in self.peer_nodes:
                node_iptables = self.get_iptables_configuration(
                    node, ipv6=is_ipv6)

                self.log('info', '3. Checking if correct ports '
                                 'are open on {0}'.format(node))
                self._check_ports(node, node_iptables,
                                  firewall_test_data.DEFAULT_MN_IP4_6_PORTS)

                self.log('info', '4. Checking if correct ports '
                                 'are closed on {0}'.format(node))
                self._check_ports(node, node_iptables,
                                  firewall_test_data.DEFAULT_MN_CLOSED_PORTS,
                                  False)

    @attr('all', 'revert', 'story2076', 'story2076_tc01')
    def test_02_p_create_rules(self):
        """
        @tms_id: litpcds_2076_tc01
        @tms_requirements_id: LITPCDS-2076, TORF-199859,
                    TORF-200553, TORF-214216, TORF-217079
        @tms_title: Valid LITP firewall rules creation, manually
                created rules removal
        @tms_description: Create manual and LITP firewall rules on MS
                and peer nodes. Stop plan when all "node1" rules are
                applied and recreate plan to check successful tasks not in
                new plan. After plan is rerun, verify LITP rules are in
                ip(6)tables and manual rules are removed.
        @tms_test_steps:
                @step: Verify rules created in this test are not in model
                @result: Rules not in model
                @step: Add cluster-level ip(6)tables rules to LITP model
                      with different props
                @result: Rules added successfully
                @step: Add firewall rules manually to
                        iptables/ip6tables on node1
                @result: Rules created
                @step: Verify manually created rules on node1 are in iptables
                @result: Rules in iptables
                @step: Update config rule on a node with drop_all=false
                @result: Rule is updated
                @step: Create and run plan
                @result: Plan executes successfully
                @step: Add ip(6)tables rules to LITP model under MS and
                       peer nodes with different props
                @result: Rules added successfully
                @step: Create and run plan
                @result: Plan created successfully and running
                @step: Wait for "node1" rules tasks to be successful
                @result: "node1" rules tasks are successful
                @step: Stop plan
                @result: Plan is stopped
                @step: Record tasks in stopped plan in
                        state 'initial' and 'success'
                @result: Plan states stored successfully
                @step: Re-create plan
                @result: Plan recreated successfully
                @step: Verify successful tasks not in recreated plan
                @result: Successful tasks not in recreated plan
                @step: Verify initial tasks from previous plan
                        are in recreated plan
                @result: Initial tasks in recreated plan
                @step: Run plan
                @result: Plan executes successfully
                @step: Verify iptables on MS and peer nodes
                        contain added LITP rules
                @result: Nodes have expected rules
                @step: Verify manual rules not in iptables on node1
                @result: Rules not in iptables
                @step: Verify "drop_all" rule not in iptables on node1
                @result: Rule not in iptables
        @tms_test_precondition: N/A
        @tms_execution_type: Automated """
        self.log('info', 'NOTE: The items created in this test are NOT removed'
                 ' at cleanup. test_03_p_update_rules uses these items and '
                 'removes them in that test.')

        self.log('info', '#1. Verify rules created in this test not in model.')
        rules_present = self.check_rules_in_model(self.cluster_fw_rules_lst +
                                                  self.node_ms_fw_rules_lst +
                                                  [self.drop_all_rule_false])

        self.assertFalse(rules_present, "Rule(s) to be created in this test "
                                        "already exist in LITP model.")

        self.log('info', '#2. Add cluster-level ip(6)tables rules to '
                 'LITP model with different props.')
        for rule in self.cluster_fw_rules_lst:
            self.create_update_fw_rule(
                rule, cleanup=False)

        self.log('info', '#3. Add firewall rules manually '
                         'to iptables/ip6tables on node1.')
        self.log('info', 'Triggering a Puppet run to ensure that another run '
                         'is not kicked off between the manual rules '
                         'being added and before the LITP plan runs.')
        self.start_new_puppet_run(self.ms_node, assert_success=True)

        manual_fw_rule1 = const.IPTABLES_PATH + \
            firewall_test_data.MANUAL_RULE_01
        manual_fw_rule2 = const.IP6TABLES_PATH + \
             firewall_test_data.MANUAL_RULE_02

        manual_rules_cmd = "{0}; {1}".format(manual_fw_rule1, manual_fw_rule2)
        self.run_command(self.peer_nodes[0], manual_rules_cmd, su_root=True,
                         default_asserts=True)

        self.log('info',
                 '#4. Verify manually created rules on node1 are in iptables.')
        self.check_iptables(self.peer_nodes[0],
                            firewall_test_data.MANUAL_RULE_IPV4,
                            args='-S', ipv6=False, expect_present=True)

        self.check_iptables(self.peer_nodes[0],
                            firewall_test_data.MANUAL_RULE_IPV6,
                            args='-S', ipv6=True, expect_present=True)

        self.log('info', '#5. Update config rule on node1 with '
                 '"drop_all=false".')
        self.create_update_fw_rule(self.drop_all_rule_false,
                                   update=True, cleanup=False)

        self.log('info', '#6. Create and run plan')
        self.run_and_check_plan(self.ms_node, const.PLAN_COMPLETE,
                                plan_timeout_mins=10,
                                add_to_cleanup=False)

        self.log('info', '#7. Add ip(6)tables rules to LITP model under'
                         ' MS and peer nodes with different props.')
        for rule in self.node_ms_fw_rules_lst:
            self.create_update_fw_rule(rule, cleanup=False)

        self.log('info', '#8. Create and run plan')
        self.execute_cli_createplan_cmd(self.ms_node)
        self.execute_cli_runplan_cmd(self.ms_node, add_to_cleanup=False)

        self.log('info', '#9. Restart litpd service once all node1 '
                         'tasks are successful and wait for plan to '
                         'transition to state "Stopped".')
        self.restart_litpd_when_task_state(
            self.ms_node, 'Unlock VCS on node "{0}"'.format(
                self.peer_nodes[0]),
            task_state=const.PLAN_TASKS_RUNNING)

        self.log('info', '#10. Record tasks in stopped plan in state '
                 '"Initial" and state "Success".')
        successful = self.get_plan_task_states(self.ms_node,
                                               const.PLAN_TASKS_SUCCESS)
        initial_plan1 = self.get_plan_task_states(self.ms_node,
                                                  const.PLAN_TASKS_INITIAL)

        successful_tasks_plan1 = [task['MESSAGE'] for task in successful]
        initial_tasks_plan1 = [task['MESSAGE'] for task in initial_plan1]

        self.log('info', '#11. Re-create plan.')
        self.execute_cli_createplan_cmd(self.ms_node)

        self.log('info', '#12. Verify "Success" tasks from '
                         'previous plan are not in recreated plan.')
        stdout, _, _ = self.execute_cli_showplan_cmd(self.ms_node)
        self.assertNotEqual([], stdout)

        for task in successful_tasks_plan1:
            if "Lock" in task or "Unlock" in task:
                continue

            self.log('info', 'Verify successful task "{0}" not '
                             'in recreated plan'.format(task))
            self.assertFalse(self.is_text_in_list(task, stdout),
                             'Previously Successful task "{0}" found in '
                             'recreated plan:\n\n"{1}"'.format(task, stdout))

        self.log('info', '#13. Verify "Initial" tasks from '
                         'previous plan are in recreated plan')

        initial_plan2 = self.get_plan_task_states(self.ms_node,
                                                  const.PLAN_TASKS_INITIAL)

        initial_tasks_plan2 = [task['MESSAGE'] for task in initial_plan2]

        for task in initial_tasks_plan1:
            if "Lock" in task or "Unlock" in task:
                continue

            self.log('info',
                     'Verify task "{0}" in recreated plan'.format(task))
            self.assertTrue(self.is_text_in_list(task, initial_tasks_plan2),
                            'Previously Initial task "{0}" not found in '
                            'recreated plan:\n\n"{1}"'.format(task, stdout))

        self.log('info', '#14. Run recreated plan')
        self.execute_cli_runplan_cmd(self.ms_node, add_to_cleanup=False)

        self.assertTrue(self.wait_for_plan_state(
            self.ms_node, const.PLAN_COMPLETE, timeout_mins=10),
            'Plan execution did not succeed.')

        self.log('info', '#15. Verify iptables on peer '
                         'nodes contain added LITP rules.')
        self.check_rules_applied(self.peer_nodes, self.rules_ms,
                                 self.rules_node)
        self.log('info',
                 '#16. Verify "drop_all" rule not in iptables on node1.')
        self.check_iptables(self.peer_nodes[0],
                            self.drop_all_rule_false["EXPECTED_RULE"],
                            args='-S', ipv6=False, expect_present=False)

        self.log('info', '#17. Verify manually created rules'
                         ' on node1 removed from iptables')
        self.check_iptables(self.peer_nodes[0],
                            firewall_test_data.MANUAL_RULE_IPV4,
                            args='-S', ipv6=False, expect_present=False)

        self.check_iptables(self.peer_nodes[0],
                            firewall_test_data.MANUAL_RULE_IPV6,
                            args='-S', ipv6=True, expect_present=False)

    @attr('all', 'revert', 'story2076', 'story2076_tc03')
    def test_03_p_update_remove_rules(self):
        """
        @tms_id: litpcds_2076_tc18
        @tms_requirements_id: LITPCDS-2076, TORF-199859,
                            TORF-200553, TORF-214216
        @tms_title: Update and remove LITP firewall rules
        @tms_description: Update various firewall rule properties and
        verify iptables are updated correctly. Reboot node1 and verify
        rules persist. Remove all rules and verify rules are removed
        from iptables.
        @tms_test_steps:
            @step: Verify test_02_p_create_rules has run
            @result: Test has been run
            @step: Update firewall rules on MS and nodes
                    with different properties
            @result: Rules updated successfully
            @step: Create and run plan
            @result: Plan ran successfully
            @step: Verify updates applied in iptables
            @result: Updates applied
            @step: Reboot node1
            @result: Reboot successful
            @step: Verify updated rules persist in iptables on node1
            @result: Rules persist
            @step: Remove all test rules
            @result: Rules are in "ForRemoval" state
            @step: Update config rule on a node with drop_all=true
            @result: Config rule updated successfully
            @step: Create and run plan
            @result: Plan completed successfully
            @step: Verify "drop_all" rule in iptables on node1
            @result: "drop_all" rule in iptables
            @step: Verify all test rules removed from iptables
            @result: Rules removed from iptables
        @tms_test_precondition: NA
        @tms_execution_type: Automated
        """
        self.log('info', 'NOTE: test_02_p_create_rules must be run before '
                 'this test as rules created there are needed for this test.')
        self.log('info', '#1. Verify test_02_p_create_rules has run.')
        rules_present = self.check_rules_in_model(self.cluster_fw_rules_lst +\
                                                  self.node_ms_fw_rules_lst)

        if not rules_present:
            self.log('info', 'test_02_p_create_rules has not run. '
                     'Running test now...')
            self.test_02_p_create_rules()
            self.log('info', 'test_02_p_create_rules successfully run. '
                     'Starting test_03_p_update_rules now...')

        self.log('info', '#2. Update firewall rules with different properties')
        for rule in self.update_fw_rules_lst:
            self.create_update_fw_rule(rule, cleanup=False, update=True)

        self.log('info', '#3. Create and run plan.')
        self.run_and_check_plan(self.ms_node, const.PLAN_COMPLETE,
                                plan_timeout_mins=10)

        self.log('info', '#4. Verify updates applied in iptables.')
        self.check_rules_applied(self.peer_nodes, self.updated_rules_ms,
                                 self.updated_rules_node)

        self.log('info', '#5. Reboot node "{0}".'.format(self.peer_nodes[0]))
        self.poweroff_peer_node(self.ms_node, self.peer_nodes[0])
        self.poweron_peer_node(self.ms_node, self.peer_nodes[0])

        self.log('info', '#6. Verify rules persist in iptables '
                 'on {0}.'.format(self.peer_nodes[0]))
        self.check_rules_applied(self.peer_nodes[0], self.updated_rules_ms,
                                 self.updated_rules_node)

        self.log('info', '#7. Remove all test rules and verify '
                         'rules are in "ForRemoval" state.')
        for rule in self.cluster_fw_rules_lst + self.node_ms_fw_rules_lst:
            parent_path = self.get_rule_parent_path(rule["TYPE"])

            for rule_path_name in rule["PATH_NAME"]:
                fw_path = "{0}/{1}".format(parent_path, rule_path_name)

                self.execute_cli_remove_cmd(self.ms_node, fw_path)

                self.log('info', 'Verify rule "{0}" has state "ForRemoval"'
                         .format(rule_path_name))

                state = self.get_item_state(self.ms_node, fw_path)
                self.assertEqual("ForRemoval", state)

                if rule["TYPE"] == "node":
                    self.execute_cli_remove_cmd(self.ms_node, fw_path.replace(
                                                self.fw_rules_n1_path,
                                                self.fw_rules_n2_path))
                    self.log('info', 'Verify rule "{0}" has state "ForRemoval"'
                             .format(rule_path_name))

                    state = self.get_item_state(self.ms_node, fw_path)
                    self.assertEqual("ForRemoval", state)

        self.log('info', '#8. Update config rule on node1 to drop_all=true')
        self.create_update_fw_rule(self.drop_all_rule_true,
                                   update=True, cleanup=False)

        self.log('info', '#9. Create and run plan.')
        self.run_and_check_plan(self.ms_node, const.PLAN_COMPLETE,
                                plan_timeout_mins=10)

        self.log('info', '#10. Verify "drop_all" rule in '
                         'iptables on peer nodes.')
        self.check_iptables(self.peer_nodes[0],
                            self.drop_all_rule_false["EXPECTED_RULE"],
                            args='-S', ipv6=False, expect_present=True)

        self.log('info', '#11. Verify all test rules removed.')
        self.check_rules_applied(self.peer_nodes, self.rules_ms,
                                 self.rules_node, expect_present=False)

#!/usr/bin/env python

'''
COPYRIGHT Ericsson 2019
The copyright to the computer program(s) herein is the property of
Ericsson Inc. The programs may be used and/or copied only with written
permission from Ericsson Inc. or in accordance with the terms and
conditions stipulated in the agreement/contract under which the
program(s) have been supplied.

@since:     Sept 2017
@author:    Philip Daly
@summary:   STORY LITPCDS-214216
            As a LITP user I want to be able to configure a firewall rule
            with a single source or destination port specified and not have
            '-m multiports' included in the corresponding
            iptables/ip6tables rule that is configured.
'''

import test_constants
from litp_cli_utils import CLIUtils
import os
from litp_generic_test import GenericTest, attr
import json


class Story214216(GenericTest):
    '''
    As a LITP user I want to be able to configure a firewall rule
    with a single source or destination port specified and not have
    '-m multiports' included in the corresponding
    iptables/ip6tables rule that is configured.
    '''
    IP_TABLES = "iptables"
    IP6_TABLES = "ip6tables"
    INPUT = "INPUT"
    OUTPUT = "OUTPUT"

    def setUp(self):
        """
        Description:
            Runs before every single test
        Actions:
            1. Call the super class setup method
            2. Set up variables used in the tests
        Results:
            The super class prints out diagnostics and variables
            common to all tests are available.
        """
        self.dummy_for_pylint_obsoletion = attr()
        super(Story214216, self).setUp()
        self.ms1 = self.get_management_node_filename()
        self.mn1, self.mn2 = self.get_managed_node_filenames()[:2]
        self.test_nodes = self.get_managed_node_filenames()
        self.cli = CLIUtils()

    def tearDown(self):
        """
        Description:
            Runs after every single test
        Actions:
            1. Perform Test Cleanup
        Results:
            Items used in the test are cleaned up and the
            super class prints out end test diagnostics
        """
        super(Story214216, self).tearDown()

    def _create_fw_config(self, config_name, cluster_config=True):
        """
        Description:
            Creates firewall config and links to firewall rule
        Args:
            config_name(str): ID to be used for object creation
                              in the LITP URL.
            cluster_config(bool): Specifies whether the URL
                                  is at cluster level or node
                                  level in the LITP model.
        Actions:
            1. Create firewall config
        Results:
            Path in litp tree to the created firewall config
        """
        collection_type = "collection-of-cluster-config"
        config_type = "firewall-cluster-config"

        if not cluster_config:
            collection_type = "collection-of-node-config"
            config_type = "firewall-node-config"

        coll_of_config_url = self.find(self.ms1,
                                       "/deployments", collection_type)[0]

        fw_config_urls = self.find(self.ms1,
                                   coll_of_config_url, config_type)

        if len(fw_config_urls) == 0:
            fw_config_url = '{0}/{1}'.format(coll_of_config_url, config_name)
            self.execute_cli_create_cmd(self.ms1,
                                        fw_config_url, config_type)
        else:
            fw_config_url = fw_config_urls[0]

        return fw_config_url

    def _update_fw_rule_props_list(self, url, item_id, props, delete=False):
        """
        Description:
            Update firewall rule
        Args:
            url (str): firewall url
            item_id (str): firewall rule name
            props (str): properties to be updated
        Actions:
            1. Update firewall rule
        Results:
            Path in litp tree to the updated firewall rule
        """
        firewall_rule = url + "/rules/{0}".format(item_id)
        if delete:
            self.execute_cli_update_cmd(
                self.ms1, firewall_rule, props, action_del=delete)
        else:
            self.execute_cli_update_cmd(
                self.ms1, firewall_rule, props)

    def _create_run_and_wait_for_plan_state(self, state, err_msg, timeout=60):
        """
        Description
            Create and run plan and wait for specified plan state

        Args:
            state   (int): The state we want the plan to reach
                           must be one of the value defined on test_constants
            err_msg (str): Assertion error message
            timeout (int): Max time allocated for state to be reached
        """
        plan_states = {
        test_constants.PLAN_COMPLETE: 'completed',
        test_constants.PLAN_IN_PROGRESS: 'running',
        test_constants.PLAN_NOT_RUNNING: 'not running (all tasks in Initial)',
        test_constants.PLAN_FAILED: 'failed',
        test_constants.PLAN_STOPPED: 'stopped',
        test_constants.PLAN_STOPPING: 'stopping',
        test_constants.PLAN_INVALID: 'invalid'}

        self.assertTrue(state in plan_states,
            'Invalid plan state "{0}" was specified'.format(state))

        self.execute_cli_createplan_cmd(self.ms1)
        self.execute_cli_runplan_cmd(self.ms1)

        self.assertTrue(self.wait_for_plan_state(self.ms1, state,
                                                 timeout_mins=timeout),
          '\nExpected plan state "{0}" was not reached "{1}mins\n{2}"'
          .format(plan_states[state], timeout, err_msg))

    def _get_iptables_configuration(self, nodes, providers, tables):
        """
        Description:
            Show iptable configuration
        Args:
            nodes    (list) : The nodes on which to run iptables command
            providers (list) : Specify IPv4 or IPv6 version
            tables (list): Specifies the types of ip tables to be checked.
                           [filter, raw, mangle, nat]
        Return:
            iptables (dict): firewall data
        """
        iptables = {}
        for node in nodes:
            iptables[node] = {}
            for provider in providers:
                iptables[node][provider] = {}
                for table in tables:
                    if provider == self.IP6_TABLES and table == 'nat':
                        continue
                    cmd = '/sbin/{0} -S --table {1}'.format(provider, table)
                    self.log('info',
                             '"{0}" firewall configuration "{1}"'.
                             format(provider, node))

                    iptables[node][provider][table] = \
                        self.run_command(node, cmd, su_root=True,
                                         default_asserts=True)[0]
        return iptables

    @staticmethod
    def _is_rule_in_iptables(rule_elements, iptables_contents):
        """
        Description
            Check if given rule is present in iptbales of specified version
        Args:
            iptables_contents (list): contents of ip tables
            rule_elements (list): Expected rules to be found on firewall

        Example of rule_elements:
            ['-A INPUT', '-p tcp', '--comment "005 ipv4"', '-j ACCEPT']
        """
        for line in iptables_contents:
            if all(pattern in line for pattern in rule_elements):
                if '-m multiport' not in rule_elements:
                    if '-m multiport' in line:
                        return False
                return True
        return False

    def _check_all_expected_rules_are_applied(self, nodes,
                                              iptables_contents, rule_set):
        """
        Description:
            Check that all expected firewall rule are applied

        Args:
            nodes (list) : List of node on which to check firewall config
            iptables_contents (dict): iptables contents
            rule_set (dict): Expected firewall rules
        """
        missing_rules = []
        extra_rules = []
        for node in nodes:
            for case, data in sorted(rule_set.iteritems()):
                if data.get('nodes') and node not in data.get('nodes'):
                    continue

                table = data.get('table', 'filter')

                for provider in [self.IP6_TABLES, self.IP_TABLES]:
                    if provider == self.IP6_TABLES and table == 'nat':
                        continue
                    if provider == self.IP_TABLES:
                        expected_rules = data.get('expected_ipv4_rules', [])
                    else:
                        expected_rules = data.get('expected_ipv6_rules', [])

                    for rule in expected_rules:
                        found = self._is_rule_in_iptables(rule,
                                    iptables_contents[node][provider][table])

                        log_str = \
                            '{0} {1:<9} {2:<8} {3} {4}'. \
                            format(node, provider, table, case, ' '.join(rule))

                        if not found and "Deletes" not in case:
                            missing_rules.append(log_str)
                            self.log('info', 'F {0}'.format(log_str))
                        elif found and "Deletes" in case:
                            extra_rules.append(log_str)
                            self.log('info', 'F {0}'.format(log_str))
                        else:
                            self.log('info', '  {0}'.format(log_str))
        return missing_rules, extra_rules

    def _load_rule_set(self, rule_set_file):
        """
        Description:
            Load JASON data structure that describes the set of firwall rules
            to use for the test
        Args:
            rule_set_file (str): File to read in rules from
        """
        cmd = "[ -f {0} ]".format(rule_set_file)
        _, _, rc = self.run_command_local(cmd)
        self.assertEqual(0, rc)
        rule_set = None
        with open(rule_set_file, 'r') as infile:
            rule_set = json.load(infile)
        return rule_set

    def _create_update_rules(self, rule_set, fw_conf_url_node, rule_names=None,
                             node=True, update=False, initial_rules=None,
                             cleanup=True):
        """
        Description:
            Create and/or update firewall rules in litp model
        Args:
            rule_set(dict): dictionary of rules to be applied
            fw_conf_url_node(string): url to fw config in model
            rule_names(list): list of rule names if needs to be updated
            node(bool): set to True if rules are applied on node
            update(bool): set to True if update is required
            initial_rules (list): The original IP table rules.
            cleanup (bool): Specifies whether the command should
                            be torn down at the end of the auto test.
        Return:
            N/A
        """
        if rule_names is None:
            rule_names = []
        for i, case in enumerate(sorted(rule_set.keys()), 1):
            self.log("info", 'Adding rule: {0}'.format(case))
            if "identifier" in rule_set[case]:
                rule_name = rule_set[case]['identifier']
            elif node:
                rule_name = 'fw_story214216_n_rule_{0}'.format(i)
            else:
                rule_name = 'fw_story214216_rule_{0}'.format(i)

            rule_set[case]['url'] = ('{0}/rules/{1}'
                                     .format(fw_conf_url_node, rule_name))
            if update == False:
                self.execute_cli_create_cmd(self.ms1,
                                            rule_set[case]['url'],
                                            "firewall-rule",
                                            rule_set[case]['props'],
                                            add_to_cleanup=cleanup)
            if initial_rules is not None:
                import re
                string_tmp = rule_set[case]['props']
                # getting rule name from the dictionary for later use
                new_added_rule = (re.search(r'\d{3}.[a-zA-Z0-9]+'
                                    r'', string_tmp).group()) + ' ipv4'
                initial_rules.append(new_added_rule)

            if update and 'delete_obj' not in rule_set[case]:
                if 'delete_prop' in rule_set[case]:
                    self._update_fw_rule_props_list(
                        fw_conf_url_node,
                        rule_name,
                        rule_set[case]['delete_prop'],
                        True)
                elif 'updated_prop' in rule_set[case]:
                    self._update_fw_rule_props_list(
                        fw_conf_url_node,
                        rule_name,
                        rule_set[case]['updated_prop'])
                rule_names.append(rule_name)
            elif update and 'delete_obj' in rule_set[case]:
                self.execute_cli_remove_cmd(self.ms1,
                                            rule_set[case]['url'],
                                            add_to_cleanup=False)

    def _assert_rules_applied(self, rules, extra=False):
        """
        Description:
            Assert that all rules are applied
        Args:
            rules(list): list of rules missing or extra in iptables.
            extra (bool): Flag as to whether the rules were not expected.
        Return:
            N/A
        """
        if extra == False:
            self.assertEqual([], rules)
        self.assertEqual([], rules)

    def _vcs_reboot_and_wait_for_system(self, active_system, reboot_system,
                                        system_timeout_mins=5,
                                        group_timeout_mins=2):
        """
        Reboot a system and wait for is to rejoin the VCS cluster. Also waits
        for all group instances to start on the system.

        Args:
            active_system (str): An active VCS system to use to check for
                system states.
            reboot_system (str): The system to wait for SysState=Running and
                any groups on that system to start.
            system_timeout_mins (int): Timeout to wait for the system to get
                into state Running.
            group_timeout_mins (int): Timeout to wait for groups on the system
                to start.
        """
        self.poweroff_peer_node(self.ms1, reboot_system)
        self.log('info', 'Powered off {0}, powring on.'.format(reboot_system))
        self.poweron_peer_node(self.ms1, reboot_system)
        self.log('info', 'Powered on {0}.'.format(reboot_system))
        self.log('info', 'Waiting for VCS and groups to start on {0}.'.format(
                reboot_system))
        timout_seconds = system_timeout_mins * 60
        wait_cmd = '/opt/VRTSvcs/bin/hasys -wait {0} ' \
                   'SysState Running -time {1}'.format(reboot_system,
                                                       timout_seconds)
        _, _, exit_code = self.run_command(active_system,
                                           wait_cmd,
                                           su_root=True)
        if exit_code != 0:
            run_cmd = "hastatus -sum"
            output, _, _ = self.run_command(active_system,
                                            run_cmd,
                                            su_root=True)
            self.log('info', 'Services failed to start: {0}'.format(output))

        self.assertEqual(0, exit_code)

        self.log('info', 'VCS system started, waiting for groups.')
        self.wait_for_all_starting_vcs_groups(self.mn1,
                                              group_timeout_mins)

    #@attr('pre-reg', 'non-revert', 'story214216', 'story214216_tc01')
    def obsolete_01_p_create_firewall_rules(self):
        """
        Obsoleted as functionality moved to test_02_p_create_rules
            in testset_firewall_rule_positive.py

        @#tms_id: torf_214216_tc01
        @#tms_requirements_id: TORF-214216
        @#tms_title: Test creation of firewall rules of a variety of sport
        & dport configurations in both IPV4 & IPV6.
        @#tms_description: Test to verify that firewall rules of a variety
        of sport & dport configurations in both IPV4 & IPV6 can be
        successfully deployed and that the -m multiport argument is
        only added to the rule when more than one port is specified
        for either sport, dport, or both.
        @#tms_test_steps:
            @step: Deploy a series of new firewall rules.
            @result: New firewall rules are deployed successfully.
        @#tms_test_precondition:NA
        @#tms_execution_type: Automated
        """
        initial_rules = []
        # As we create rules at node and cluster level, creating two lists
        # to check the rules separately
        all_nodes = [self.mn1, self.mn2]
        node_1 = [self.mn1]
        all_providers = [self.IP_TABLES, self.IP6_TABLES]
        all_tables = ['filter', 'raw', 'mangle', 'nat']

        self.log('info',
                 '1. Define firewall rules to be use in this test')
        rule_set_file = ('{0}/test_01_rule_set_story214216'.
                         format(os.path.dirname(__file__)))

        rule_set = self._load_rule_set(rule_set_file)
        rule_set_nodefile = ('{0}/test_01_rule_set_story214216_node'.
                             format(os.path.dirname(__file__)))

        rule_set_node = self._load_rule_set(rule_set_nodefile)

        self.log('info',
                 '2. Create cluster firewall config items')
        fw_conf_url_cluster = self._create_fw_config(
                                                "fw_story214216_config")
        fw_conf_url_node = self._create_fw_config("fw_story214216_node_config",
                                                  False)

        self.log('info',
                 '3. Create firewall rule items at cluster level')
        self._create_update_rules(rule_set, fw_conf_url_cluster,
                                  initial_rules=initial_rules, cleanup=False)
        self._create_update_rules(rule_set_node, fw_conf_url_node, node=True,
                                  initial_rules=initial_rules, cleanup=False)
        # Sorted list of initial rules names, needed for order check later on
        initial_rules_sorted = sorted(initial_rules)

        self.log('info',
                 '4. Create and run plan')
        self._create_run_and_wait_for_plan_state(test_constants.PLAN_COMPLETE,
                                                 'Plan to deploy firewall'
                                                 ' rules failed')

        self.log('info',
                 '5. Log "iptables" configuration after creating new rules')
        iptables = self._get_iptables_configuration(all_nodes, all_providers,
                                                    all_tables)

        self.log('info',
                 '7. Check that the rules have been added to firewalls')
        missing_rules, extra_rules = \
        self._check_all_expected_rules_are_applied(
            all_nodes, iptables, rule_set)
        missing_rules_node, extra_rules_node = \
        self._check_all_expected_rules_are_applied(
            node_1, iptables, rule_set_node)

        for rules in missing_rules, missing_rules_node:
            self._assert_rules_applied(rules)
        for rules in extra_rules, extra_rules_node:
            self._assert_rules_applied(rules, extra=True)

        self.log('info',
                 '8. Check the rules order')
        order_rules = []
        # If the rule with name is in iptables, remember its index
        applied_rules = iptables[self.mn1][self.IP_TABLES]["filter"]
        for name in initial_rules_sorted:
            for rule in applied_rules:
                if name in rule:
                    order_rules.append(applied_rules.index(rule))
        # order_rules list contains indexes for input rules on odd places
        # and output rules on even places. (e.g. [0,10,1,11]
        #  So we slice the list to have two
        # lists containing input and output rules indexes
        input_rules_indexes = order_rules[::2]
        output_rules_indexes = order_rules[1::2]
        # Here we compare the indexes list with its sorted copy - if the order
        # is correct, they are the same and cmp returns code 0
        compare_input_lists = cmp(input_rules_indexes,
                                  sorted(input_rules_indexes))
        compare_output_lists = cmp(output_rules_indexes,
                                   sorted(output_rules_indexes))
        self.assertEqual(compare_input_lists, 0)
        self.assertEqual(compare_output_lists, 0)

        self.log('info', '9. Reboot the nodes')
        self._vcs_reboot_and_wait_for_system(self.mn2, self.mn1)
        self._vcs_reboot_and_wait_for_system(self.mn1, self.mn2)

        self.log('info',
                 '10. Check that the following rules persist after reboot')
        missing_rules, extra_rules = \
        self._check_all_expected_rules_are_applied(
            all_nodes, iptables, rule_set)
        missing_rules_node, extra_rules_node = \
        self._check_all_expected_rules_are_applied(
            node_1, iptables, rule_set_node)
        for rules in missing_rules, missing_rules_node:
            self._assert_rules_applied(rules)
        for rules in extra_rules, extra_rules_node:
            self._assert_rules_applied(rules, extra=True)

    #@attr('pre-reg', 'non-revert', 'story214216', 'story214216_tc02')
    def obsolete_02_p_update_firewall_rules(self):
        """
        Obsoleted as functionality moved to test_03_p_update_remove_rules
            in testset_firewall_rule_positive.py

        @#tms_id: torf_214216_tc02
        @#tms_requirements_id: TORF-214216
        @#tms_title: Test updating of firewall rules.
        @#tms_description: Test to verify that user can update firewall
        rules and that the -m multiport argument is updated accordingly.
        @#tms_test_steps:
            @step: Update the firewall rules deployed in test 01.
            @result: The firewall rules are successfully updated.
         @#tms_test_precondition:NA
        @#tms_execution_type: Automated
        """
        # As we create rules at node and cluster level, creating two lists
        # to check the rules separately
        all_nodes = [self.mn1, self.mn2]
        node_1 = [self.mn1]
        all_providers = [self.IP_TABLES, self.IP6_TABLES]
        all_tables = ['filter', 'raw', 'mangle', 'nat']
        self.log('info',
                 '1. Define firewall rules to be used in this test')
        rule_set_file = ('{0}/test_02_rule_set_story214216_update'.
                         format(os.path.dirname(__file__)))
        rule_set = self._load_rule_set(rule_set_file)
        rule_set_nodefile = ('{0}/test_02_rule_set_story214216_update_node'.
                             format(os.path.dirname(__file__)))
        rule_set_node = self._load_rule_set(rule_set_nodefile)
        cluster_rule_names = []
        node_rule_names = []

        self.log('info',
                 '2. Create firewall config items')
        fw_conf_url_cluster = self._create_fw_config(
                                                "fw_story214216_config")
        fw_conf_url_node = self._create_fw_config("fw_story214216_node_config",
                                                  False)

        self.log('info',
                 '3. Create and update firewall rule items at cluster '
                 'and node level')

        self._create_update_rules(rule_set, fw_conf_url_cluster,
                                  cluster_rule_names, update=True)
        self._create_update_rules(rule_set_node, fw_conf_url_node,
                                  node_rule_names, node=True, update=True)

        self.log('info',
                 '4. Create and run plan')
        self._create_run_and_wait_for_plan_state(test_constants.PLAN_COMPLETE,
                                                 'Plan to deploy firewall'
                                                 ' rules failed')

        self.log('info',
                 '5. Log "iptables" configuration after creating new rules')
        iptables = self._get_iptables_configuration(all_nodes, all_providers,
                                                    all_tables)

        self.log('info',
                 '6. Check that the rules have been added to firewalls')
        missing_rules, extra_rules = \
        self._check_all_expected_rules_are_applied(
            all_nodes, iptables, rule_set)
        missing_rules_node, extra_rules_node = \
        self._check_all_expected_rules_are_applied(
            node_1, iptables, rule_set_node)

        for rules in missing_rules, missing_rules_node:
            self._assert_rules_applied(rules)
        for rules in extra_rules, extra_rules_node:
            self._assert_rules_applied(rules, extra=True)

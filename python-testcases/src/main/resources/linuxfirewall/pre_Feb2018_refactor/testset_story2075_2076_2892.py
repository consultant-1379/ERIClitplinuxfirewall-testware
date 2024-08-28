#!/usr/bin/env python

'''
COPYRIGHT Ericsson 2019
The copyright to the computer program(s) herein is the property of
Ericsson Inc. The programs may be used and/or copied only with written
permission from Ericsson Inc. or in accordance with the terms and
conditions stipulated in the agreement/contract under which the
program(s) have been supplied.

@since:     May 2014, refactored Dec 2015, refactored Aprr 2016
@author:    Priyanka/Maria; Maurizio,Terry
@summary:   STORY LITPCDS-2075
            As a LITP User, I want to create a list of IPv4 or IPv6 firewall
            rules that can be applied to any node, so that I can benefit from
            the increased security
            LITPCDS-2076
            As a LITP User, I want to remove/update extra firewall rules to
            an already applied configuration, so that I can enhance or modify
            my firewall configuration
            LITPCDS-2892
            As an application designer I want MCollective to use SSL so that
            broadcasting to nodes is more secure
            TORF-106903
            As a LITP developer, I do not want any UT or AT in plugins to be
            dependent on undefined internal Model Manager logic.
            Converted existing ATs (created with stories LITPCDS-2075 and
            LITPCDS-2076) into ITs.
'''

import test_constants
from litp_cli_utils import CLIUtils
import os
from litp_generic_test import GenericTest, attr
import json


class Story2075Story2076(GenericTest):
    '''
    As a LITP User, I want to create,remove and update a list of IPv4 or
    IPv6 firewall rules that can be applied to any node,
    so that I can benefit from the increased security
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
        super(Story2075Story2076, self).setUp()
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
        super(Story2075Story2076, self).tearDown()

    def _create_fw_config(self, config_name, cluster_config=True):
        """
        Description:
            Creates firewall config and links to firewall rule
        Args:
            config_name(str): config_name
            cluster_config(bool): True
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

    def _create_fw_rule_item(self, fw_config_url, item_id, props):
        """
        Description:
            Create firewall in the test firewall config at url
        Args:
            fw_config_url (str): firewall configuration item url
            item_id       (str): firewall rule item id
            props         (str): firewall rule options
        Returns:
            firewall_rule (str): firewall rule url
        """
        firewall_rule = '{0}/rules/{1}'.format(fw_config_url, item_id)
        self.execute_cli_create_cmd(
            self.ms1, firewall_rule, "firewall-rule", props)
        return firewall_rule

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

    def _update_fw_rule_remove_props_list(self, url, item_id, props):
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
        self.execute_cli_update_cmd(
            self.ms1, firewall_rule, props, action_del=True)
        return firewall_rule

    def _remove_fw_rule(self, url, item_id):
        """
        Description:
            remove a firewall rule
        Args:
            url (str): path to firewall rule
            fw_rule__name (str): firewall rule name
        Actions:
            1. Remove firewall rule
        Results:
            Path in litp tree to the removed firewall rule
        """
        firewall_rule = url + "/rules/{0}".format(item_id)
        self.execute_cli_remove_cmd(
            self.ms1, firewall_rule)

    def _create_fw_rule_props_by_kw(self, url, item_id, **kwargs):
        """
        Description:
            Create firewall in the test firewall config at url
        Args:
            url (str): firewall url
            firewall_name (str): firewall name
        Actions:
            1. Create firewall
        Results:
            Path in litp tree to the created firewall
        """
        firewall_rule = url + "/rules/{0}".format(item_id)
        pairs = ["=".join([name, value]) for name, value in kwargs.iteritems()]
        props = " ".join(pairs)
        self.execute_cli_create_cmd(
            self.ms1, firewall_rule, "firewall-rule", props)
        return firewall_rule

    def _check_iptables(self, node, fw_rule, ip_tables="both", inout="both",
            expect_positive=True, assert_result=True):
        """
        Description:
        Method to check iptable contains rule
        """
        # decide what commands to run and negative check
        ip_tables_check_commands = [self.IP_TABLES, self.IP6_TABLES]
        ip_tables_n_chk_cmds = []
        if ip_tables != "both":
            ip_tables_n_chk_cmds = list(
                set.difference(set(ip_tables_check_commands), set([ip_tables]))
            )
            ip_tables_check_commands = [ip_tables]

        # decide which channels to check and negative check
        inout_tables_checks = [self.INPUT, self.OUTPUT]
        inout_tables_negative_checks = []
        if inout != "both":
            inout_tables_negative_checks = list(
                set.difference(set(inout_tables_checks), set([inout]))
            )
            inout_tables_checks = [inout]

        # the command "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l"
        # will issue the command (iptables, ip6tables) output and grep for
        # input or output which is then checked for the check string.
        # finally a word count hit is returned and checked
        results = []
        for command in ip_tables_check_commands:
            for check in inout_tables_checks:
                std_out, std_err, rc = self.run_command(
                    node,
                    "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l"
                    .format(command, check, fw_rule),
                    su_root=True)

                if assert_result:
                    self.assertEquals([], std_err)
                    self.assertEqual(expect_positive,
                            self.is_text_in_list("1", std_out))
                    self.assertEquals(0, rc)
                else:
                    self.assertNotEqual([], std_out)
                    results.append(std_out[0])

        # same as prevuious but negative checks i.e. if something is setup
        # for only output ipv6, then it should not appear in ipv4 or input
        for command in ip_tables_n_chk_cmds:
            for check in inout_tables_negative_checks:
                std_out, std_err, rc = self.run_command(
                    node,
                    "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l"
                    .format(command, check, fw_rule),
                    su_root=True)

                if assert_result:
                    self.assertEquals([], std_err)
                    self.assertTrue(self.is_text_in_list("0", std_out))
                    self.assertEquals(0, rc)
                else:
                    self.assertNotEqual([], std_out)
                    results.append(std_out[0])

        if not assert_result:
            return results

    def _assert_iptables_rule(self, node, rules_list, section=None):
        ''' Asserts a given rule exists in the iptables file.
            Example:
        '''
        return self._assert_iptables_rule_by_file(
            node, rules_list, test_constants.IPTABLES_V4_PATH, section)

    def _assert_iptables_rule_v6(self, node, rules_list, section=None):
        ''' Same as self._assert_iptables_rule() except it tests
            the IPV6 version of iptables
        '''
        return self._assert_iptables_rule_by_file(
            node, rules_list, test_constants.IPTABLES_V6_PATH, section)

    def _assert_iptables_rule_by_file(self, node, rules_list, iptable_file,
                                      section=None):
        '''Same as self._assert_iptables_rule.
        Asserts a given rule exists in the specified file.
        '''
        ip_tables_etc = self.get_file_contents(node, iptable_file,
                                               su_root=True)
        self.assertTrue(ip_tables_etc)

        currentsection = None
        # for each line in the ip_tables file
        for line in ip_tables_etc:
            # find the current section for searching
            if line.startswith(":"):
                currentsection = line.lstrip(':').split(" ")[0]
            # match criteria: rule must be in the line,
            #                rule is in search list
            #                rule is in the interested section
            elif all((rule in line) for rule in rules_list) and \
                    (not section or section == currentsection):
                print "Line matched: {0} with {1}".format(line, rules_list)
                return True
        # didn't returm a match so is not found
        self.assertFalse(True, "Cannot find rules in {0} {1}: {2}".format(
            iptable_file, section or "", rules_list))

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

                        if not found:
                            missing_rules.append(log_str)
                            self.log('info', 'F {0}'.format(log_str))
                        else:
                            self.log('info', '  {0}'.format(log_str))

        return missing_rules

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
        self.assertEqual(0, rc,
            'File "{0}" was not found on local machine'.format(rule_set_file))
        rule_set = None
        with open(rule_set_file, 'r') as infile:
            rule_set = json.load(infile)
        return rule_set

    def _check_cli_errors(self, expected_errors, actual_errors,
                                                    check_extra_error=True):
        """
        Description:
            Compare expected errors with actual errors
        Args:
            expected_errors (dict)   : Data structure that contains expected
                                       error details
            actual_errors (list)     : List of errors posted by LITP
            check_extra_error (bool) : Specify whether to check for extra
                                       error messages
        Note:
            Example of expected_errors data structure:
                expected_errors = [
                    {
                        'url': '/my/path/to/item1',              # Optional
                        'error_type': 'InvalidRequestError',     # Optional
                        'error_msg': '   Plan already running'   # Required
                    }
                    ...
                ]
        """
        missing = []
        extra = []
        for expected in expected_errors:

            self.assertTrue('msg' in expected,
                '"msg" field is required in expected error data')

            expected_msg = [expected.get('msg'),
                            expected.get('error_type', '')]

            if 'url' in expected:
                for i, actual in enumerate(actual_errors[:], 0):
                    if expected['url'] == actual and \
                       i < (len(actual_errors) - 1) and \
                       all(
                        [msg in actual_errors[i + 1] for msg in expected_msg]):
                        del actual_errors[i]
                        del actual_errors[i]
                        break
                else:
                    missing.append(expected['url'])
                    missing.append(''.join(expected_msg))
            else:
                for i, actual in enumerate(actual_errors[:], 0):
                    if all(msg in actual for msg in expected_msg):
                        del actual_errors[i]
                        break
                else:
                    missing.append(''.join(expected_msg))

        # We expect actual_error list to be empty at this point
        # any element still in it is to be considered as extra error
        if check_extra_error:
            for error in actual_errors:
                extra.append(error)

        return missing, extra

    def _create_update_rules(self, rule_set, fw_conf_url_node, rule_names=None,
                             node=True, update=False, initial_rules=None):
        """
        Description:
            Create and/or update firewall rules in litp model
        Args:
            rule_set(dict): dictionary of rules to be applied
            fw_conf_url_node(string): url to fw config in model
            rule_names(list): list of rule names if needs to be updated
            node(bool): set to True if rules are applied on node
            update(bool): set to True if update is required
        Return:
            N/A
        """
        if rule_names is None:
            rule_names = []
        for i, case in enumerate(sorted(rule_set.keys()), 1):
            self.log("info", 'Adding rule: {0}'.format(case))
            if node:
                rule_name = 'fw_story200553_n_rule_{0}'.format(i)
            else:
                rule_name = 'fw_story200553_rule_{0}'.format(i)

            rule_set[case]['url'] = ('{0}/rules/{1}'
                                     .format(fw_conf_url_node, rule_name))

            self.execute_cli_create_cmd(self.ms1,
                                        rule_set[case]['url'],
                                        "firewall-rule",
                                        rule_set[case]['props'])
            if initial_rules is not None:
                import re
                string_tmp = rule_set[case]['props']
                # getting rule name from the dictionary for later use
                new_added_rule = (re.search(r'\d{3}.[a-zA-Z0-9]+'
                                    r'', string_tmp).group()) + ' ipv4'
                initial_rules.append(new_added_rule)

            if update:
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

    def _assert_rules_applied(self, missing_rules):
        """
        Description:
            Assert that all rules are applied
        Args:
            missing_rules(list): list of rules missing in iptables, if any
        Return:
            N/A
        """
        self.assertEqual([], missing_rules,
                         '\nFollowing firewall rules were not found\n{0}'.
                         format('\n'.join(missing_rules)))

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

        self.assertEqual(0, exit_code,
                         msg='Timedout waiting for {0} to join '
                             'cluster!'.format(reboot_system))

        self.log('info', 'VCS system started, waiting for groups.')
        self.wait_for_all_starting_vcs_groups(self.mn1,
                                              group_timeout_mins)

    #@attr('pre-reg', 'revert', 'story2076', 'story2076_tc01')
    def obsolete_01_p_create_firewall_rule_positive_validation(self):
        """
        Obsoleted as functionality moved to test_02_p_create_rules and
        test_03_p_update_remove_rules in testset_firewall_rule_positive.py

        @#tms_id: litpcds_2076_tc01
        @#tms_requirements_id: LITPCDS-2076
        @#tms_title: Test firewall rule positive validation
        @#tms_description: Test firewall rule positive validation
        @#tms_test_steps:
            @step: Read firewall default configuration
            @result: Iptables initial config saved
            @step: Create firewall rules to be use in this test
            @result: firewall rules created
            @step: Create a rules with different "name" property values
            @result: Rules created successfully in litp model
            @step: Create a rules with different "Proto" property values
            @result: Rules created successfully in litp model
            @step: Create a rules with different "Action" property values
            @result: Rules created successfully in litp model
            @step: Create a rules with different Source/Dest port values
            @result: Rules created successfully in litp model
            @step: Create a rules with different Packet state values
            @result: Rules created successfully in litp model
            @step: Create a rules with different IN/OUT values
            @result: Rules created successfully in litp model
            @step: Create a rules with different ICMP values
            @result: Rules created successfully in litp model
            @step: Create a rules with different Table values
            @result: Rules created successfully in litp model
            @step: Create a rules with different FORWARD, PREROUTING &
                POSTROUTING values
            @result: Rules created successfully in litp model
            @step: Duplicate rule with same name on different chains
            @result: Rule created in litp model
            @step: Identical rules with unique names
            @result: Rule created in litp model
            @step: Create cluster firewall config item
            @result: Rule created in litp model
            @step: Create firewall rule items at cluster level
            @result: Rule created in litp model
            @step: Create and run plan
            @result: Plan is created and runs successfully
            @step: Log "iptables" configuration after creating new rules
            @result: "iptables" are logged
            @step: Check that the following rules have been added to firewalls
            @result: rules have been added to firewalls
            @step: Remove created rules
            @result: Rules removed
            @step: Read current firewall configuration
            @result: current firewall configuration read
            @step: Verify that firewall configuration is back to default config
            @result: firewall configuration is back to default config
        @#tms_test_precondition:NA
        @#tms_execution_type: Automated
        """
        all_nodes = [self.mn1, self.mn2]
        all_providers = [self.IP_TABLES, self.IP6_TABLES]
        all_tables = ['filter', 'raw', 'mangle', 'nat']
        self.log('info',
        '1. Read firewall default configuration')
        iptables_initial_config = self._get_iptables_configuration(
                                        all_nodes, all_providers, all_tables)

        self.log('info',
        '2. Define firewall rules to be use in this test')
        rule_set_file = ('{0}/test_01_rule_set_story2075_2076_2892'.
                         format(os.path.dirname(__file__)))
        rule_set = self._load_rule_set(rule_set_file)

        self.log('info',
        '3. Create cluster firewall config item')
        fw_conf_url = self._create_fw_config("fw_story2075_tc01_config")

        self.log('info',
        '4. Create firewall rule items at cluster level')
        for i, case in enumerate(sorted(rule_set.keys()), 1):
            self.log("info", 'Positive validation test: {0}'.format(case))

            rule_set[case]['url'] = ('{0}/rules/fw_story2075_tc01_{1}'
                                     .format(fw_conf_url, i))

            self.execute_cli_create_cmd(self.ms1,
                                        rule_set[case]['url'],
                                        "firewall-rule",
                                        rule_set[case]['props'])

        self.log('info',
        '5. Create and run plan')
        self._create_run_and_wait_for_plan_state(test_constants.PLAN_COMPLETE,
                'Plan to deploy firewall rules failed')

        self.log('info',
        '6. Log "iptables" configuration after creating new rules')
        iptables = self._get_iptables_configuration(all_nodes, all_providers,
                                                    all_tables)

        self.log('info',
        '7. Check that the following rules have been added to firewalls')
        missing_rules = self._check_all_expected_rules_are_applied(
                                        all_nodes, iptables, rule_set)

        self.assertEqual([], missing_rules,
                         '\nFollowing firewall rules were not found\n{0}'.
                         format('\n'.join(missing_rules)))

        self.log('info',
        '8. Remove created rules')
        for case in sorted(rule_set.keys()):
            self.execute_cli_remove_cmd(self.ms1, rule_set[case]['url'])

        self._create_run_and_wait_for_plan_state(test_constants.PLAN_COMPLETE,
            'Plan to remove firewall rules created during test failed')

        self.log('info',
        '9. Read current firewall configuration')
        iptables_current_config = self._get_iptables_configuration(
                                        all_nodes, all_providers, all_tables)

        self.log('info',
        '10. Verify that firewall configuration is back to deafult config')
        for node in all_nodes:
            for provider in all_providers:
                for table in all_tables:
                    if provider == self.IP6_TABLES and table == 'nat':
                        continue
                    self.assertEqual(
                        iptables_initial_config[node][provider][table],
                        iptables_current_config[node][provider][table],
                        'Firewall configuration did not reset to default '
                        'after removing all rules created during test')

    #@attr('pre-reg', 'revert', 'story2076', 'story2076_tc02')
    def obsolete_02_n_create_firewall_rule_negative_validation(self):
        """
        Obsoleted as functionality moved to ATs:
            ERIClitplinuxfirewall:
                test_02_n_create_firewall_rule_negative_validation.at
            ERIClitplinuxfirewallapi:
                test_02_n_create_firewall_rule_negative_validation.at

        @#tms_id: litpcds_2076_tc02
        @#tms_requirements_id: LITPCDS-2076
        @#tms_title: Validation errors at "create" and "create_plan"
        @#tms_description: Test validation errors at "create" and "create_plan"
        @#tms_test_steps:
            @step: Try create rules with combinations of invalid values
                for properties
            @result: All created commands are rejected with the expected
                ValidationError messages are outputted
            @step: Try create rules with reserved chain numbers
            @result: expected ValidationError message outputted
            @step: Create rule to check Numbering in the name (chain position)
                must be unique
            @result: expected ValidationError msg outputted on create_plan
            @step: Create rule to check cluster level rule and a node level
                rule cannot have the same chain order
            @result: expected ValidationError msg outputted on create_plan
            @step: Create rule to check scenario described by Bug LITPCDS-9746
            @result: expected ValidationError msg outputted on create_plan
        @#tms_test_precondition:NA
        @#tms_execution_type: Automated
        """

        rule_set_file = ('{0}/test_02_rule_set_story2075_2076_2892'.
                         format(os.path.dirname(__file__)))
        rule_set = self._load_rule_set(rule_set_file)

        cluster_fw_config_url = self._create_fw_config("config")
        cluster_fw_rule_url = cluster_fw_config_url + "/rules/fw002n"

        for rule in rule_set:
            self.log('info', 'Rule:     "{0}"'.format(rule['description']))
            for error in rule['expected_errors']:
                self.log('info', 'Expected: "{0}"'.format(error['msg']))

            _, stderr, _ = self.execute_cli_create_cmd(
                           self.ms1, cluster_fw_rule_url, 'firewall-rule',
                           rule['props'], expect_positive=False)

            missing, extra = self._check_cli_errors(rule['expected_errors'],
                                                    stderr)
            self.assertEqual([], missing,
                '\nMISSING ERRORS:\n{0}'.format('\n'.join(missing)))
            self.assertEqual([], extra,
                '\nEXTRA ERRORS:\n{0}'.format('\n'.join(extra)))

        self.log('info',
            'Rule: 58. Numbering in the name (chain position) must be unique')

        cluster_fw1 = cluster_fw_config_url + "/rules/fw0021"
        cluster_fw2 = cluster_fw_config_url + "/rules/fw0022"
        cluster_fw3 = cluster_fw_config_url + "/rules/fw0023"

        self.execute_cli_create_cmd(self.ms1, cluster_fw1,
                                    "firewall-rule", "name='010 elias'")
        self.execute_cli_create_cmd(self.ms1, cluster_fw2,
                                    "firewall-rule", "name='010 job'")
        self.execute_cli_create_cmd(self.ms1, cluster_fw3,
                                    "firewall-rule", "name='10 elias'")

        expected_errors = [
            {
                'url': '/deployments/d1/clusters/c1/configs/fw_config_init'
                       '/rules/fw0021',
                'msg': "ValidationError    Create plan failed: Position '10' "
                       "in the firewall chain 'INPUT' is not unique on "
                       "cluster 'c1'"
            },
            {
                'url': '/deployments/d1/clusters/c1/configs/fw_config_init'
                       '/rules/fw0022',
                'msg': "ValidationError    Create plan failed: Position '10' "
                       "in the firewall chain 'INPUT' is not unique on "
                       "cluster 'c1'"
            },
            {
                'url': '/deployments/d1/clusters/c1/configs/fw_config_init'
                       '/rules/fw0023',
                'msg': "ValidationError    Create plan failed: Position '10' "
                       "in the firewall chain 'INPUT' is not unique on "
                       "cluster 'c1'"
            },
            {
                'url': '/deployments/d1/clusters/c1/configs/fw_config_init'
                       '/rules/fw0021',
                'msg': "ValidationError    Create plan failed: Position '10' "
                       "in the firewall chain 'OUTPUT' is not unique on "
                       "cluster 'c1'"
            },
            {
                'url': '/deployments/d1/clusters/c1/configs/fw_config_init'
                       '/rules/fw0022',
                'msg': "ValidationError    Create plan failed: Position '10' "
                       "in the firewall chain 'OUTPUT' is not unique on "
                       "cluster 'c1'"
            },
            {
                'url': '/deployments/d1/clusters/c1/configs/fw_config_init'
                       '/rules/fw0023',
                'msg': "ValidationError    Create plan failed: Position '10' "
                       "in the firewall chain 'OUTPUT' is not unique on "
                       "cluster 'c1'"
            },
            {
                'url': '/deployments/d1/clusters/c1/configs/fw_config_init'
                       '/rules/fw0021',
                'msg': "ValidationError    Create plan failed: Position '10' "
                       "in the firewall chain 'INPUT' is not unique on node "
                       "'node1'"
            },
            {
                'url': '/deployments/d1/clusters/c1/configs/fw_config_init'
                       '/rules/fw0022',
                'msg': "ValidationError    Create plan failed: Position '10' "
                       "in the firewall chain 'INPUT' is not unique on node "
                       "'node1'"
            },
            {
                'url': '/deployments/d1/clusters/c1/configs/fw_config_init'
                       '/rules/fw0023',
                'msg': "ValidationError    Create plan failed: Position '10' "
                       "in the firewall chain 'INPUT' is not unique on node "
                       "'node1'"
            },
            {
                'url': '/deployments/d1/clusters/c1/configs/fw_config_init'
                       '/rules/fw0021',
                'msg': "ValidationError    Create plan failed: Position '10' "
                       "in the firewall chain 'OUTPUT' is not unique on node "
                       "'node1'"
            },
            {
                'url': '/deployments/d1/clusters/c1/configs/fw_config_init'
                       '/rules/fw0022',
                'msg': "ValidationError    Create plan failed: Position '10' "
                       "in the firewall chain 'OUTPUT' is not unique on node "
                       "'node1'"
            },
            {
                'url': '/deployments/d1/clusters/c1/configs/fw_config_init'
                       '/rules/fw0023',
                'msg': "ValidationError    Create plan failed: Position '10' "
                       "in the firewall chain 'OUTPUT' is not unique on node "
                       "'node1'"
            },
            {
                'url': '/deployments/d1/clusters/c1/configs/fw_config_init'
                       '/rules/fw0021',
                'msg': "ValidationError    Create plan failed: Position '10' "
                       "in the firewall chain 'INPUT' is not unique on node "
                       "'node2'"
            },
            {
                'url': '/deployments/d1/clusters/c1/configs/fw_config_init'
                       '/rules/fw0022',
                'msg': "ValidationError    Create plan failed: Position '10' "
                       "in the firewall chain 'INPUT' is not unique on node "
                       "'node2'"
            },
            {
                'url': '/deployments/d1/clusters/c1/configs/fw_config_init'
                       '/rules/fw0023',
                'msg': "ValidationError    Create plan failed: Position '10' "
                       "in the firewall chain 'INPUT' is not unique on node "
                       "'node2'"
            },
            {
                'url': '/deployments/d1/clusters/c1/configs/fw_config_init'
                       '/rules/fw0021',
                'msg': "ValidationError    Create plan failed: Position '10' "
                       "in the firewall chain 'OUTPUT' is not unique on node "
                       "'node2'"
            },
            {
                'url': '/deployments/d1/clusters/c1/configs/fw_config_init'
                       '/rules/fw0022',
                'msg': "ValidationError    Create plan failed: Position '10' "
                       "in the firewall chain 'OUTPUT' is not unique on node "
                       "'node2'"
            },
            {
                'url': '/deployments/d1/clusters/c1/configs/fw_config_init'
                       '/rules/fw0023',
                'msg': "ValidationError    Create plan failed: Position '10' "
                       "in the firewall chain 'OUTPUT' is not unique on node "
                       "'node2'"
            }
        ]

        _, stderr, _ = self.execute_cli_createplan_cmd(self.ms1,
                                                       expect_positive=False)
        missing, extra = self._check_cli_errors(expected_errors, stderr)
        self.assertEqual([], missing,
            '\nMISSING ERRORS:\n{0}'.format('\n'.join(missing)))
        self.assertEqual([], extra,
            '\nEXTRA ERRORS:\n{0}'.format('\n'.join(extra)))

        self.execute_cli_remove_cmd(self.ms1, cluster_fw1)
        self.execute_cli_remove_cmd(self.ms1, cluster_fw2)
        self.execute_cli_remove_cmd(self.ms1, cluster_fw3)

        self.log('info',
            '59. cluster level rule and a node level rule cannot have '
            'the same chain order')

        node_fw_config_url = self._create_fw_config(
                                      "mynodefwconfig", cluster_config=False)

        cluster_fw_rule_url = cluster_fw_config_url + "/rules/fw0024"
        self.execute_cli_create_cmd(self.ms1,
                                    cluster_fw_rule_url,
                                    "firewall-rule",
                                    props="name='252 cluster rule'")

        node_fw_rule_url = node_fw_config_url + "/rules/fw0025"
        self.execute_cli_create_cmd(self.ms1,
                                    node_fw_rule_url,
                                    "firewall-rule",
                                    props="name='252 node rule'")

        expected_errors = [
            {
                'url': cluster_fw_rule_url,
                'msg': 'ValidationError    Create plan failed: Position '
                       '\'252\' in the firewall chain \'OUTPUT\' is not '
                       'unique on node \'node1\''
            },
            {
                'url': cluster_fw_rule_url,
                'msg': 'ValidationError    Create plan failed: Position '
                       '\'252\' in the firewall chain \'INPUT\' is not '
                       'unique on node \'node1\''
            },
            {
                'url': node_fw_rule_url,
                'msg': 'ValidationError    Create plan failed: Position '
                       '\'252\' in the firewall chain \'OUTPUT\' is not '
                       'unique on node \'node1\''
            },
            {
                'url': node_fw_rule_url,
                'msg': 'ValidationError    Create plan failed: Position '
                       '\'252\' in the firewall chain \'INPUT\' is not '
                       'unique on node \'node1\''
            }
        ]

        _, stderr, _ = self.execute_cli_createplan_cmd(self.ms1,
                                                       expect_positive=False)
        missing, extra = self._check_cli_errors(expected_errors, stderr)
        self.assertEqual([], missing,
            '\nMISSING ERRORS:\n{0}'.format('\n'.join(missing)))
        self.assertEqual([], extra,
            '\nEXTRA ERRORS:\n{0}'.format('\n'.join(extra)))

        self.execute_cli_remove_cmd(self.ms1, cluster_fw_rule_url)
        self.execute_cli_remove_cmd(self.ms1, node_fw_rule_url)

        self.log('info',
            '60. Scenario described by Bug LITPCDS-9746')

        cluster_fw_rule_url1 = cluster_fw_config_url + "/rules/fw0026"
        self.execute_cli_create_cmd(self.ms1,
                                    cluster_fw_rule_url1,
                                    "firewall-rule",
                                    props="name='11119 my rule'")

        cluster_fw_rule_url2 = cluster_fw_config_url + "/rules/fw0027"
        self.execute_cli_create_cmd(self.ms1,
                                    cluster_fw_rule_url2,
                                    "firewall-rule",
                                    props="name='111119 my rule'")

        expected_errors = [
            {
                'url': cluster_fw_rule_url1,
                'msg': 'ValidationError    Create plan failed: Position '
                       '\'11119\' in the \'OUTPUT\' chain conflicts with '
                       'position \'111119\' in the \'INPUT\' chain on node '
                       '\'node1\''
            },
            {
                'url': cluster_fw_rule_url2,
                'msg': 'ValidationError    Create plan failed: Position '
                       '\'111119\' in the \'INPUT\' chain conflicts with '
                       'position \'11119\' in the \'OUTPUT\' chain on node '
                       '\'node1\''
            },
            {
                'url': cluster_fw_rule_url1,
                'msg': 'ValidationError    Create plan failed: Position '
                       '\'11119\' in the \'OUTPUT\' chain conflicts with '
                       'position \'111119\' in the \'INPUT\' chain on node '
                       '\'node2\''
            },
            {
                'url': cluster_fw_rule_url2,
                'msg': 'ValidationError    Create plan failed: Position '
                       '\'111119\' in the \'INPUT\' chain conflicts with '
                       'position \'11119\' in the \'OUTPUT\' chain on node '
                       '\'node2\''
            },
            {
                'url': cluster_fw_rule_url1,
                'msg': 'ValidationError    Create plan failed: Position '
                       '\'11119\' in the \'OUTPUT\' chain conflicts with '
                       'position \'111119\' in the \'INPUT\' chain on cluster '
                       '\'c1\''
            },
            {
                'url': cluster_fw_rule_url2,
                'msg': 'ValidationError    Create plan failed: Position '
                       '\'111119\' in the \'INPUT\' chain conflicts with '
                       'position \'11119\' in the \'OUTPUT\' chain on cluster '
                       '\'c1\''
            }
         ]

        _, stderr, _ = self.execute_cli_createplan_cmd(self.ms1,
                                                       expect_positive=False)
        missing, extra = self._check_cli_errors(expected_errors, stderr)
        self.assertEqual([], missing,
            '\nMISSING ERRORS:\n{0}'.format('\n'.join(missing)))
        self.assertEqual([], extra,
            '\nEXTRA ERRORS:\n{0}'.format('\n'.join(extra)))

        self.execute_cli_remove_cmd(self.ms1, cluster_fw_rule_url1)
        self.execute_cli_remove_cmd(self.ms1, cluster_fw_rule_url2)

    #@attr('pre-reg', 'revert', 'story2076', 'story2076_tc04')
    def obsolete_04_p_check_firewall_config_creates_default_rules(self):
        """
        Obsoleted as functionality moved to test_01_p_default_ports in
            testset_firewall_rule_positive.py

        @#tms_id: litpcds_2076_tc04
        @#tms_requirements_id: LITPCDS-2076
        @#tms_title: check firewall config creates default rules
        @#tms_description: Verify that correct set of ports are open by default
        @#tms_test_steps:
            @step: Find firewall cluster config already in the model
            @result: firewall cluster config in the model are stored
            @step: Find firewall ms config already in model
            @result: firewall MS config in the model are stored
            @step: Check iptables & ip6tables on MS contain correct rules
            @result: iptables & ip6tables on MS contain correct rules
            @step: Check iptables & ip6tables on M contain correct rules
            @result: iptables & ip6tables on MN contain correct rules
        @#tms_test_precondition:NA
        @#tms_execution_type: Automated
        """
        test_ms_ip4_6_ports = ["22", "67", "68", "69", "80", "123",
                               "443", "8139", "8140", "9999",
                               "4369", "9100", "9101", "9102", "9103",
                               "9104", "9105", "12987", "61613", "61614"]

        test_mn_ip4_6_ports = ["22", "80", "123", "8139", "8140", "9999",
                               "4369", "9100", "9101", "9102", "9103",
                               "9104", "9105", "12987", "61614"]

        # Make sure cluster "firewall config item" and
        # "firewall ms config" item exist in the mode
        self.find(self.ms1, "/deployments", "firewall-cluster-config")
        self.find(self.ms1, "/ms", "firewall-node-config")

        # Check iptables on ms contain correct rules
        for port in test_ms_ip4_6_ports:
            self._check_iptables(
                self.ms1, 'dport | /bin/grep -w {0}'.format(port),
                ip_tables=self.IP_TABLES)
        for port in test_ms_ip4_6_ports:
            self._check_iptables(
                self.ms1,
                'dport | /bin/grep -w {0}'.format(port),
                ip_tables=self.IP6_TABLES)

        # Check iptables on peer nodes contain correct rules
        for node in self.test_nodes:
            for port in test_mn_ip4_6_ports:
                self._check_iptables(
                    node, 'dport | /bin/grep -w {0}'.format(port),
                    ip_tables=self.IP_TABLES)
            for port in test_mn_ip4_6_ports:
                self._check_iptables(
                    node,
                    'dport | /bin/grep -w {0}'.format(port),
                    ip_tables=self.IP6_TABLES)

    #@attr('pre-reg', 'revert', 'cdb_priority1', 'story2076', 'story2076_tc05')
    def obsolete_05_p_create_remove_firewall_rules_cluster_node_level(self):
        """
        Obsoleted as functionality moved to test_01_p_load_rules_from_XML
            in testset_firewall_load_rules_xml.py

        @#tms_id: litpcds_2076_tc05
        @#tms_requirements_id: LITPCDS-2076
        @#tms_title: create remove firewall rules cluster node level
        @#tms_description: Test that a set of rules can be created at cluster
            and node level and verify that the rule's propagation logic works
            Define different firewall rules at cluster level,
            node1 level and node2 level and test that cluster level
            rules are present on all nodes in that cluster and
            that rules created at node level are only present on
            that node and that all cluster level and node level rules
            can be removed.
        @#tms_test_steps:
            @step: Create firewall rules under existing node & cluster configs
            @result: A cluster level firewall rule is added to the model
            @result: A node level firewall rule is added to node1 in the model
            @result: A node level firewall rule is added to node2 in the model
            @step: Create and run a plan to remove the firewall-node-config
                for node2
            @result: Plan is run successfully
            @result: Iptables are updated and contain correct rules
            @result: node1 rule & cluster level rule still exists the iptables
            @step: Create and run a plan to remove firewall-cluster-config
            @result: Plan is run successfully
            @result: Iptables are updated and contain correct rules
            @step: Create and run a plan to remove firewall-node-config
                for node1
            @result: Plan is run successfully
            @result: Rules have been removed from the iptables
        @#tms_test_precondition:NA
        @#tms_execution_type: Automated
        """
        # System must have at least 2 nodes to continue
        nodes_path = self.find(self.ms1, "/deployments", "node", True)
        self.assertTrue(
            len(nodes_path) > 1,
            "The LITP Tree has less than 2 nodes defined")
        node1_path = nodes_path[0]
        node2_path = nodes_path[1]
        test_node1 = self.get_node_filename_from_url(self.ms1, node1_path)
        test_node2 = self.get_node_filename_from_url(self.ms1, node2_path)

        # Find firewall cluster config already in model
        fw_cluster_config = self.find(
            self.ms1, "/deployments", "firewall-cluster-config")[0]

        # Define cluster level firewall rule
        props = ('name="050 test05cluster"'
                 ' dport="22,80,111,443,3000,25151,9999"')
        fw_cluster = self._create_fw_rule_item(
            fw_cluster_config, "fw001", props)

        # Find firewall-node-config for node1
        node1_config_path = self.find(
            self.ms1, node1_path, "firewall-node-config")[0]

        # Define a node level firewall rule for node1 with provider=iptables
        props = ('name="051 test05node1" provider="iptables" '
                'dport="662,875,2020,2049,4001,4045"')
        fw_node1 = self._create_fw_rule_item(
            node1_config_path, "fw002", props)

        # find firewall-node-config for node2
        node2_config_path = self.find(
            self.ms1, node2_path, "firewall-node-config")[0]

        # Define a node level firewall rule for node2 with provider=ip6tables
        props = ('name="052 test05node2" provider="ip6tables" '
                 'dport="2144,7080,7443"')
        fw_node2 = self._create_fw_rule_item(
            node2_config_path, "fw003", props)

        # Create plan
        self.execute_cli_createplan_cmd(self.ms1)

        # Run plan
        self.execute_cli_runplan_cmd(self.ms1)

        # Wait for plan to complete
        self.assertTrue(self.wait_for_plan_state(
            self.ms1, test_constants.PLAN_COMPLETE))

        # Check tables contain correct rules
        for node in self.test_nodes:
            self._check_iptables(node, "test05cluster")

        self._check_iptables(
            test_node1, "test05node1", ip_tables=self.IP_TABLES)
        self._check_iptables(
            test_node2, "test05node2", ip_tables=self.IP6_TABLES)

        # Remove firewall-node-config for node2
        self.execute_cli_remove_cmd(self.ms1, fw_node2)

        # Create plan
        self.execute_cli_createplan_cmd(self.ms1)

        # Run plan
        self.execute_cli_runplan_cmd(self.ms1)

        # Wait for plan to complete
        self.assertTrue(self.wait_for_plan_state(
            self.ms1, test_constants.PLAN_COMPLETE))

        # Check that the node2 rule has been removed from the ip6tables
        cmd_to_run = \
            "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l".format(
            self.IP6_TABLES, self.INPUT, "test05node2")

        self.assertTrue(
            self.wait_for_puppet_action(
            self.ms1, test_node2, cmd_to_run, 0, "0", True))

        # Check that the node1 rule exists in iptables
        # and cluster level rule exists in iptables and ip6tables
        for node in self.test_nodes:
            self._check_iptables(node, "test05cluster")
        self._check_iptables(
            test_node1, "test05node1", ip_tables=self.IP_TABLES)

        # Remove firewall-cluster-config
        self.execute_cli_remove_cmd(self.ms1, fw_cluster)

        # Create plan
        self.execute_cli_createplan_cmd(self.ms1)

        # Run plan
        self.execute_cli_runplan_cmd(self.ms1)

        # Wait for plan to complete
        self.assertTrue(self.wait_for_plan_state(
            self.ms1, test_constants.PLAN_COMPLETE))

        # Check cluster level rule has been removed from
        # the iptables and ip6tables
        cmd_to_run = \
            "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l".format(
            self.IP_TABLES, self.INPUT, "test05cluster")

        for node in self.test_nodes:
            self.assertTrue(
                self.wait_for_puppet_action(
                self.ms1, node, cmd_to_run, 0, "0", True))

        cmd_to_run = \
            "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l".format(
            self.IP6_TABLES, self.INPUT, "test05cluster")

        for node in self.test_nodes:
            self.assertTrue(
                self.wait_for_puppet_action(
                self.ms1, node, cmd_to_run, 0, "0", True))

        # Remove firewall-node-config for node1
        self.execute_cli_remove_cmd(self.ms1, fw_node1)

        # Create plan
        self.execute_cli_createplan_cmd(self.ms1)

        # Run plan
        self.execute_cli_runplan_cmd(self.ms1)

        # Wait for plan to complete
        self.assertTrue(self.wait_for_plan_state(
            self.ms1, test_constants.PLAN_COMPLETE))

        # Check node1 rule has been removed from the iptables
        cmd_to_run = \
            "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l".format(
            self.IP_TABLES, self.INPUT, "test05node1")

        self.assertTrue(
            self.wait_for_puppet_action(
            self.ms1, test_node1, cmd_to_run, 0, "0", True))

    #@attr('pre-reg', 'revert', 'story2076', 'story2076_tc08')
    def obsolete_08_p_create_firewall_rule_disable(self):
        """
        Obsoleted as functionality moved to test_02_p_create_rules and
        test_03_p_update_remove_rules in testset_firewall_rule_positive.py

        @#tms_id: litpcds_2076_tc08
        @#tms_requirements_id: LITPCDS-2076
        @#tms_title: create firewall rule disable
        @#tms_description: Test that dropall property disables rule
        @#tms_test_steps:
            @step: specify config rule on a cluster with drop_all=true
            @result: Rule is created
            @step: specify drop_all=false on node1
            @result: Rule is created
            @step: Create plan & Run plan
            @result: Plan is run successfully
            @result: connection is blocked from the nodes
            @step: Remove the created cluster level config and node config
            @result: Items are in ForRemoval state
            @step: Create plan & Run plan
            @result: Plan is run successfully
            @result: connection is no longer blocked from the nodes
        @#tms_test_precondition:NA
        @#tms_execution_type: Automated
        """
        nodes_path = self.find(self.ms1, "/deployments", "node", True)
        self.assertTrue(
            len(nodes_path) > 1,
            "The LITP Tree has less than 2 nodes defined")
        node1_path = nodes_path[0]
        node2_path = nodes_path[1]
        test_node1 = self.get_node_filename_from_url(self.ms1, node1_path)
        test_node2 = self.get_node_filename_from_url(self.ms1, node2_path)

        # Find firewall node config already in model
        node1_config_path = self.find(
            self.ms1, node1_path, "firewall-node-config")[0]

        try:
            # Update dropall property
            props = ('drop_all="false"')

            self.execute_cli_update_cmd(
                self.ms1, node1_config_path, props)

            # Create plan
            self.execute_cli_createplan_cmd(self.ms1)

            # Run plan
            self.execute_cli_runplan_cmd(self.ms1)

            # Wait for plan to complete
            self.assertTrue(self.wait_for_plan_state(
                self.ms1, test_constants.PLAN_COMPLETE))

            # Check drop all rule has been removed from node1
            cmd_to_run = \
            "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l".format(
            self.IP_TABLES, self.INPUT, "999 drop all")

            self.assertTrue(
                self.wait_for_puppet_action(
                self.ms1, test_node1, cmd_to_run, 0, "0", True))

            # Check drop all rule is still present on node2
            self._check_iptables(test_node2, '"999 drop all"')

        finally:
            # Update dropall property
            props = ('drop_all="true"')

            self.execute_cli_update_cmd(
                self.ms1, node1_config_path, props)

            # Create plan
            self.execute_cli_createplan_cmd(self.ms1)

            # Run plan
            self.execute_cli_runplan_cmd(self.ms1)

            # Wait for plan to complete
            self.assertTrue(self.wait_for_plan_state(
                self.ms1, test_constants.PLAN_COMPLETE))

    #@attr('pre-reg', 'revert', 'cdb_tmp', 'story2076', 'story2076_tc13')
    def obsolete_13_p_firewall_rules_export_load_xml(self):
        """
        Obsoleted as functionality moved to ATs:
            ERIClitplinuxfirewall:
                test_13_p_firewall_rules_export_load_xml.at

        @#tms_id: litpcds_2076_tc13
        @#tms_requirements_id: LITPCDS-2076
        @#tms_title: firewall rules with export & load xml
        @#tms_description: Verify firewall rules can be exported and loaded
        @#tms_test_steps:
            @step: Find existing firewall cluster config
            @result: Firewall cluster config in the model are stored
            @step: Create a firewall cluster rule
            @result: firewall cluster rule created
            @step: Find exisitng firewall node config
            @result: Firewall node config in the model are stored
            @step: Create a firewall node rule
            @result: firewall node rule created
            @step: Export the firewall cluster config
            @result: Item exported successfully
            @step: Export the firewall node config
            @result: Item exported successfully
            @step: Export the firewall cluster rule
            @result: Item exported successfully
            @step: Export the firewall node rule
            @result: Item exported successfully
            @step: remove the service firewall
            @result: service firewall is removed
            @step: Load the firewall cluster config into model
            @result: XML file is loaded successfully
            @step: Load the firewall cluster rule into the model using merge
            @result: XML file is loaded successfully
            @step: Load the firewall node config into model
            @result: XML file is loaded successfully
        @#tms_test_precondition:NA
        @#tms_execution_type: Automated
        """
        # Find cluster configs path
        cluster_config_path = self.find(
            self.ms1, "/deployments", "collection-of-cluster-config")[0]

        # Find firewall cluster config already in model
        fw_cluster_config = self.find(
            self.ms1, "/deployments", "firewall-cluster-config")[0]

        # Find node1 path
        node1_path = self.find(self.ms1, "/deployments", "node", True)[0]

        # Find node1 config path
        n1_config_path = self.find(
            self.ms1, node1_path, "collection-of-node-config")[0]

        # Find node1 cluster config already in model
        fw_node_config = self.find(
            self.ms1, node1_path, "firewall-node-config")[0]

        # Export existing cluster firewall config
        self.execute_cli_export_cmd(
            self.ms1, fw_cluster_config, "xml_13_c1config_story2075.xml")

        # Export existing node1 firewall config
        self.execute_cli_export_cmd(
            self.ms1, fw_node_config, "xml_13_n1config_story2075.xml")

        # Define cluster level firewall rule
        props = 'name="131 test13" dport="25152,25153"'
        cluster_fw_rule = self._create_fw_rule_item(
            fw_cluster_config, "fw001", props)

        # Define a node level firewall rule for node1
        props = 'name="132 test13" dport="4001,4045"'
        node_fw_rule = self._create_fw_rule_item(
            fw_node_config, "fw002", props)

        try:
            # Export export the firewall cluster config
            self.execute_cli_export_cmd(
                self.ms1, fw_cluster_config, "xml_13a_story2075.xml")

            # Export export the firewall node config
            self.execute_cli_export_cmd(
                self.ms1, fw_node_config, "xml_13b_story2075.xml")

            # Export export the firewall cluster rule
            self.execute_cli_export_cmd(
                self.ms1, cluster_fw_rule, "xml_13c_story2075.xml")

            # Export export the firewall cluster rule
            self.execute_cli_export_cmd(
                self.ms1, node_fw_rule, "xml_13d_story2075.xml")

            # Delete created firewall items
            self.execute_cli_remove_cmd(self.ms1, cluster_fw_rule)
            self.execute_cli_remove_cmd(self.ms1, fw_cluster_config)
            self.execute_cli_remove_cmd(self.ms1, node_fw_rule)
            self.execute_cli_remove_cmd(self.ms1, fw_node_config)

            # Load the firewall cluster config
            self.execute_cli_load_cmd(
                self.ms1, cluster_config_path,
                "xml_13a_story2075.xml", "--replace")

            # Load the firewall cluster rule
            self.execute_cli_load_cmd(
                self.ms1, fw_cluster_config + "/rules",
                "xml_13c_story2075.xml", "--merge")

            # Load the firewall node config
            self.execute_cli_load_cmd(
                self.ms1, n1_config_path,
                "xml_13b_story2075.xml", "--replace")

            # Create plan
            self.execute_cli_createplan_cmd(self.ms1)

        finally:
            # Load original configuration
            self.execute_cli_load_cmd(
                self.ms1, cluster_config_path,
                "xml_13_c1config_story2075.xml", "--replace")

            self.execute_cli_load_cmd(
                self.ms1, n1_config_path,
                "xml_13_n1config_story2075.xml", "--replace")

            # Create plan
            std_out, std_err, rc = self.execute_cli_createplan_cmd(
                self.ms1, expect_positive=False)
            self.assertEqual([], std_out)
            self.assertNotEqual([], std_err)
            self.assertEquals(1, rc)

    #@attr('pre-reg', 'revert', 'story2076', 'story2076_tc14')
    def obsolete_14_p_firewall_rules_stop_plan(self):
        """
        Obsoleted as functionality moved to test_02_p_create_rules
            in testset_firewall_rule_positive.py

        @#tms_id: litpcds_2076_tc14
        @#tms_requirements_id: LITPCDS-2076
        @#tms_title: Firewall rules & litp stop_plan
        @#tms_description: Stop plan to install firewall rules and verify that
            when the plan is recreated, only uncompleted tasks from the
            previous plan will be in the new plan
        @#tms_test_steps:
            @step: Create a node level firewall rule for node1
            @result: Firewall rule for node1 created
            @step: Create plan & Run plan
            @result: Plan is created successfully
            @step: Stop plan
            @result: Plan is stopped
            @step: Create plan & Run plan
            @result: Plan is run successfully
            @result: Iptables contain correct rules
        @#tms_test_precondition:NA
        @#tms_execution_type: Automated
        """
        # Find firewall cluster config already in model
        fw_cluster_config = self.find(
            self.ms1, "/deployments", "firewall-cluster-config")[0]

        # Define cluster level firewall rule
        self._create_fw_rule_props_by_kw(fw_cluster_config, "fw001",
                                         name='"141 test14a"',
                                         dport='"22,80,111,443,30,25151,9999"')

        nodes_path = self.find(self.ms1, "/deployments", "node", True)
        self.assertTrue(
            len(nodes_path) > 1,
            "The LITP Tree has less than 2 nodes defined")
        node1_path = nodes_path[0]
        test_node1 = self.get_node_filename_from_url(self.ms1, node1_path)

        # Find firewall-node-config for node1
        node1_config_path = self.find(
            self.ms1, node1_path, "collection-of-node-config")[0]
        fw_node1_config = self.find(
            self.ms1, node1_config_path, "firewall-node-config")[0]

        # Define a node level firewall rule for node1
        props = 'name="142 test14b" dport="662,875,2020,2049,4001,4045"'
        self._create_fw_rule_item(fw_node1_config, "fw002", props)

        # Create plan
        self.execute_cli_createplan_cmd(self.ms1)

        # Run plan
        self.execute_cli_runplan_cmd(self.ms1)

        # Stop plan
        self.execute_cli_stopplan_cmd(self.ms1)

        # Wait for plan to complete
        self.wait_for_plan_state(self.ms1, test_constants.PLAN_STOPPED)

        # Create plan
        self.execute_cli_createplan_cmd(self.ms1)

        # Run plan
        self.execute_cli_runplan_cmd(self.ms1)

        # Wait for plan to complete
        self.assertTrue(self.wait_for_plan_state(
            self.ms1, test_constants.PLAN_COMPLETE))

        # Check iptables contain correct rules
        for node in self.test_nodes:
            self._check_iptables(node, "test14a")
        self._check_iptables(test_node1, "test14b")

    #@attr('pre-reg', 'revert', 'story2076', 'story2076_tc16')
    def obsolete_16_p_update_firewall_rule_positive_validation(self):
        """
        Obsoleted as functionality moved to ATs:
            ERIClitplinuxfirewallapi:
                test_16_p_update_firewall_rule_positive_validation.at

        @#tms_id: litpcds_2076_tc16
        @#tms_requirements_id: LITPCDS-2076
        @#tms_title: Update firewall rule positive validation
        @#tms_description: Test valid updates to firewall rule validation
        @#tms_test_steps:
            @step: Create firewall rule to be use in this test
            @result: Rule is created in litp
            @step: Update firewall rule properties with different
                combination's of valid property values
            @result: All update combination's are accepted
        @#tms_test_precondition:NA
        @#tms_execution_type: Automated
        """

        # Define firewall-cluster-config
        fw_cluster_config = self._create_fw_config("myclusterfwconfig")

        # Define cluster level firewall rule with only name property provided
        props = ('name="016 test16"')
        fw_rule = self._create_fw_rule_item(fw_cluster_config,
                                                  "fw016", props)
        # 1.Update the rule to have all parameters
        update_props = ('name="160 test16" proto="udp" action="accept"'
                        ' sport="245" dport=1234-5678 state="RELATED"'
                        ' source=10.10.01.0/24 destination=129.167.122.99'
                        ' provider=iptables iniface=l0 outiface=l0 icmp=8'
                        ' chain=FORWARD log_level=crit log_prefix=String'
                        ' jump=LOG table=raw toports=17,2,33,2 '
                        ' setdscp=0xFE1 limit=5/sec')
        self._update_fw_rule_props_list(
            fw_cluster_config, "fw016", update_props)

        # Remove the firewall rule
        self.execute_cli_remove_cmd(self.ms1, fw_rule)

        valid_firewalls_rule_set = [
            ['2.Update a rules mandatory properties',
             'name="160 testing"', None],
            ['5.Update a rule with Name contains uppercase',
             'name="160 NAME"', None],
            ['6.Update a rule with Name contains multiple spaces',
             'name="160 NAME "', None],
            ['6a.Update a rule with Name begins with one digit',
             'name="2 1name"', None],
            ['6b.Update a rule with Name containing position only',
             'name="160"', None],
            ['6c.Update a rule with Name containing one digit position only',
             'name="6"', None],
            ['6d.Update a rule with Name containing a 2 digit position only',
             'name="16"', None],
            ['6e.Update a rule with Name begins with a space',
             'name=" 160 name"', None],
            ['6f.Update a rule with Name containing a chain number only and '
             'exceeding the max length', 'name="5447"', None],
            ['6g.Update Name to contain chain number exceeding the max length'
             'and to begin with a zero', 'name="01234"', None],
            ['7.Update proto from none to udp',
             'proto=udp', None],
            ['8.Update proto from udp to ospf',
             'proto=ospf', None],
            ['9.Update proto from ospf to ipv6-icmp',
             'proto=ipv6-icmp', None],
            ['10.Update proto from ipv6-icmp to all',
             'proto=all', None],
            ['14.Update action from drop to accept',
             'action=accept', None],
            ['15.Update action from accept to drop',
             'action=accept', None],
            ['16.Update source port from a range to a single entry',
             'sport=1', None],
            ['17.Update source port from a single entry to multiple entries',
             'sport=1,2,3,4,5,6,7,8', None],
            ['18.Update source port from multiple entries to a range',
             'sport=134-567', None],
            ['19.Update destination port from a range to a single entry',
             'dport=12345', None],
            ['20.Update destination port from a single entry'
             ' to multiple entries',
             'dport=12345,2,3,4,5,7,8', None],
            ['21.Update destination port from multiple entries to a range',
             'dport=1234-5678', None],
            ['22.Update state from INVALID to NEW',
             'state=NEW', None],
            ['23.Update state from NEW to ESTABLISHED',
             'state=ESTABLISHED', None],
            ['24.Update state from ESTABLISHED to RELATED',
             'state=RELATED', None],
            ['25.Update state from RELATED to INVALID',
             'state=INVALID', None],
            ['26.Update state from INVALID to NEW,ESTABLISHED,RELATED',
             'state=NEW,ESTABLISHED,RELATED', None],
            ['27.Update state from NEW,ESTABLISHED,RELATED'
             ' to ESTABLISHED,RELATED',
             'state=ESTABLISHED,RELATED', None],
            ['28.Update state from ESTABLISHED,RELATED to RELATED,ESTABLISHED',
             'state=RELATED,ESTABLISHED', None],
            ['29.Update source port from none to valid IPv4 address',
             'source=129.167.122.99 '
             'provider=iptables', None],
            ['30.Update Source port from a valid IPv4 address'
             ' to valid IPv6 range',
             'source=FF02:0:0:0:0:1:FF00:0000-FF02:0:0:0:0:1:FFFF:FFFF '
             'provider=ip6tables', None],
            ['31.Update Source port from none to a valid IPv4 subnet',
             'source=10.10.01.0/24 '
             'provider=iptables', None],
            ['32.Update Source port from a valid IPv4 subnet'
             ' to a valid IPv6 address',
             'source=1:1:1:1 '
             'provider=ip6tables', None],
            ['33.Update Source port from a valid IPv6 address'
             ' to a valid IPv6 subnet',
             'source=fe80::a00:27ff:febc:c8e1/64 '
             'provider=ip6tables', None],
            ['34.Update Source port from none to valid IPv6 range',
             'source=FF02:0:0:0:0:1:FF00:0000-FF02:0:0:0:0:1:FFFF:FFFF '
             'provider=ip6tables', None],
            ['35.Update Source port from none to a valid IPv6 subnet',
             'source=fe80::a00:27ff:febc:c8e1/64 '
             'provider=ip6tables', 'source'],
            ['36.Update destination port from none to valid IPv4 address',
             'destination=129.167.122.99 '
             'provider=iptables', None],
            ['37.Update destination port from a valid IPv4 addresss'
             ' to valid IPv4 range',
             'destination=10.10.10.5-10.10.10.10 '
             'provider=iptables', None],
            ['38.Update destination port from a valid IPv4 range'
             ' to valid IPv4 subnet',
             'destination=10.10.01.0/24 '
             'provider=iptables', None],
            ['39.Update destination port from none to valid IPv6 address',
             'destination=1:1:1:1 '
             'provider=ip6tables', None],
            ['40.Update destination port from a valid IPv6 address'
             ' to valid IPv6 range',
             'destination=FF02:0:0:0:0:1:FF00:0000-FF02:0:0:0:0:1:FFFF:FFFF '
             'provider=ip6tables', None],
            ['41.Update destination port from a valid IPv6 range'
             ' to valid IPv6 subnet',
             'destination=fe80::a00:27ff:febc:c8e1/64 '
             'provider=ip6tables', None],
            ['42.Update provider from ip6tables to none',
             'provider=ip6tables', 'destination,provider'],
            ['43.Update IN interface from none to eth0',
             'iniface=eth0', None],
            ['44.Update IN interface from eth0 to l0',
             'iniface=l0', None],
            ['45.Update OUT interface from none to eth0',
             'outiface=eth0', None],
            ['46.Update OUT interface from eth0 to l0',
             'outiface=l0', None],
            ['47.Update ICMP type from none to 0',
             'icmp=0', None],
            ['48.Update ICMP type from 0 to 8',
             'icmp=8', None],
            ['49.Update ICMP type from 8 to echo-reply',
             'icmp=echo-reply', None],
            ['50.Update ICMP type from echo-reply to echo-request ',
             'icmp=echo-request ', None],
            ['51.Update Chain type from none to INPUT',
             'chain=INPUT', None],
            ['52.Update Chain type from INPUT to OUTPUT',
             'chain=OUTPUT', None],
            ['53.Update Chain type from OUTPUT to FORWARD',
             'chain=FORWARD', None],
            ['54.Update Chain type from FORWARD to PREROUTING',
             'chain=PREROUTING', None],
            ['55.Update Chain type from PREROUTING to POSTROUTING',
             'chain=POSTROUTING', None],
            ['56.Update Chain type from POSTROUTING to none',
             'chain=POSTROUTING', 'chain'],
            ['57.Update provider from none to iptables',
             'provider=iptables', None],
            ['58.Update provider from iptables to ip6tables',
             'provider=ip6tables', None],
            ['59.Update Log Level from none to panic',
             'log_level=panic', None],
            ['60.Update Log Level from panic to alert',
             'log_level=alert', None],
            ['61.Update Log Level from alert to crit',
             'log_level=crit', None],
            ['62.Update Log Level from crit to err',
             'log_level=err', None],
            ['63.Update Log Level from err to warn',
             'log_level=warn', None],
            ['64.Update Log Level from warn to warning',
             'log_level=warning', None],
            ['65.Update Log Level from warning to notice',
             'log_level=notice', None],
            ['66.Update Log Level from notice to info',
             'log_level=info', None],
            ['67.Update Log Level from info to debug',
             'log_level=debug', None],
            ['68.Update Log Level from debug to none',
             'log_level=debug', 'log_level'],
            ['69.Update Log Prefix set to valid string',
             'log_prefix=Valid_String', None],
            ['70.Update Jump from to valid string',
             'jump=Valid_String', None],
            ['71.Update table from none to nat',
             'table=nat', None],
            ['72.Update table from nat to filter',
             'table=filter', None],
            ['73.Update table from filter to mangle',
             'table=mangle', None],
            ['74.Update table from mangle to raw',
             'table=raw', None],
            ['75.Update toports from to valid number',
             'toports=124', None],
            ['76.Update limit to valid string',
             'limit=5/sec', None],
            ['77.Update limit from one valid string to another valid string',
             'limit=56/day', None],
            ['78.Update setdscp to valid hexstring',
             'setdscp=0xFE1', None], ]

        # Define cluster level firewall rule
        props = ('name="160 test16" action="drop" sport="1234-5678"'
                 ' dport="234-345" state="INVALID" '
                 ' provider="iptables"'
                 ' log_prefix="Valid_String"')
        self._create_fw_rule_item(fw_cluster_config, "fw016", props)

        for fw_resource in valid_firewalls_rule_set:
            self.log("info", "\n*** Starting test for valid firewalls "
                     "rules data set : {0}".format(fw_resource[0]))
            self._update_fw_rule_props_list(
                fw_cluster_config, "fw016", fw_resource[1])
            if fw_resource[2]:
                self._update_fw_rule_remove_props_list(
                    fw_cluster_config, "fw016", fw_resource[2])

    #@attr('pre-reg', 'revert', 'story2076', 'story2076_tc17')
    def obsolete_17_n_update_firewall_rule_negative_validation(self):
        """
        Obsoleted as functionality moved to ATs:
            ERIClitplinuxfirewallapi:
                test_17_n_update_firewall_rule_negative_validation.at
            ERIClitplinuxfirewall:
                test_17_n_update_firewall_rule_negative_validation.at

        @#tms_id: litpcds_2076_tc17
        @#tms_requirements_id: LITPCDS-2076
        @#tms_title: Update firewall rule negative validation
        @#tms_description: Test invalid updates to firewall rule
            and validation errors
        @#tms_test_steps:
            @step: Create firewall rules to be use in this test
            @result: Rule is created in litp
            @step: Updated properties with invalid options
            @result: Updates fail with expected Validation msg
            @step: Updated properties with invalid combination of
                property values
            @result: Updates fail with expected Validation msg
            @step: Updated properties with invalid numbering in
                the name (chain position)
            @result: Updates fail with expected Validation msg
        @#tms_test_precondition:NA
        @#tms_execution_type: Automated
        """
        self.log('info',
        '1. Define firewall rules to be use in this test')
        rule_set_file = ('{0}/test_17a_rule_set_story2075_2076_2892'.
                         format(os.path.dirname(__file__)))

        rule_set = self._load_rule_set(rule_set_file)

        self.log('info', 'x. Create litp items')
        cluster_fw_config_url = self._create_fw_config("fw_2075_tc17_config")

        props = ('name="171 test17" proto="icmp" action="accept" sport="1123"'
                 ' dport="65531" state="NEW" source="129.167.122.99"'
                 ' destination="129.167.122.99" iniface="eth0" outiface="eth0"'
                 ' icmp="echo-reply" chain="INPUT" provider="iptables"'
                 ' log_level="panic" log_prefix="Valid_String"')
        cluster_fw_rule_url = self._create_fw_rule_item(cluster_fw_config_url,
                                                        "fw_tc017a",
                                                        props=props)

        for rule in rule_set:
            self.log("info", 'Rule: {0}'.format(rule['description']))
            for error in rule['expected_errors']:
                self.log('info', 'Expected: "{0}"'.format(error['msg']))

            _, stderr, _ = self.execute_cli_update_cmd(self.ms1,
                                                      cluster_fw_rule_url,
                                                      props=rule['props'],
                                                      expect_positive=False)

            missing, extra = self._check_cli_errors(rule['expected_errors'],
                                                    stderr)
            self.assertEqual([], missing,
                '\nMISSING ERRORS:\n{0}'.format('\n'.join(missing)))
            self.assertEqual([], extra,
                '\nEXTRA ERRORS:\n{0}'.format('\n'.join(extra)))

        self.log('info',
        '2. Invalid combination of property values')
        rule_set_file = ('{0}/test_17b_rule_set_story2075_2076_2892'.
                         format(os.path.dirname(__file__)))
        rule_set = self._load_rule_set(rule_set_file)

        props = 'name="172 test17"'
        cluster_fw_rule_url = self._create_fw_rule_item(cluster_fw_config_url,
                                                        "fw_tc017b",
                                                        props=props)

        for rule in rule_set:
            self.log("info", 'Rule: {0}'.format(rule['description']))
            for error in rule['expected_errors']:
                self.log('info', 'Expected: "{0}"'.format(error['msg']))

            _, stderr, _ = self.execute_cli_update_cmd(self.ms1,
                                                      cluster_fw_rule_url,
                                                      props=rule['props'],
                                                      expect_positive=False)

            missing, extra = self._check_cli_errors(rule['expected_errors'],
                                                    stderr)
            self.assertEqual([], missing,
                '\nMISSING ERRORS:\n{0}'.format('\n'.join(missing)))
            self.assertEqual([], extra,
                '\nEXTRA ERRORS:\n{0}'.format('\n'.join(extra)))

        self.log('info',
        '3. numbering in the name (chain position) must be unique')
        cluster_fw_rule_tc17_1_url = \
                            cluster_fw_config_url + "/rules/fw_tc17c_1"
        cluster_fw_rule_tc17_2_url = \
                            cluster_fw_config_url + "/rules/fw_tc17c_2"
        self.execute_cli_create_cmd(self.ms1,
                                    cluster_fw_rule_tc17_1_url,
                                    "firewall-rule",
                                    "name='173 test17c 1'")
        self.execute_cli_create_cmd(self.ms1,
                                    cluster_fw_rule_tc17_2_url,
                                    "firewall-rule",
                                    "name='174 test17c 2'")

        expected_errors = [
            {
                'url': cluster_fw_rule_tc17_1_url,
                'msg': 'ValidationError    Create plan failed: Position '
                       '\'173\' in the firewall chain \'INPUT\' is not unique '
                       'on cluster \'c1\''
            },
            {
                'url': cluster_fw_rule_tc17_1_url,
                'msg': 'ValidationError    Create plan failed: Position '
                       '\'173\' in the firewall chain \'OUTPUT\' is not '
                       'unique on cluster \'c1\''
            },
            {
                'url': cluster_fw_rule_tc17_2_url,
                'msg': 'ValidationError    Create plan failed: Position '
                       '\'173\' in the firewall chain \'INPUT\' is not '
                       'unique on cluster \'c1\''
            },
            {
                'url': cluster_fw_rule_tc17_2_url,
                'msg': 'ValidationError    Create plan failed: Position '
                       '\'173\' in the firewall chain \'OUTPUT\' is not '
                       'unique on cluster \'c1\''
            },
            {
                'url': cluster_fw_rule_tc17_1_url,
                'msg': 'ValidationError    Create plan failed: Position '
                       '\'173\' in the firewall chain \'INPUT\' is not '
                       'unique on node \'node1\''
            },
            {
                'url': cluster_fw_rule_tc17_1_url,
                'msg': 'ValidationError    Create plan failed: Position '
                       '\'173\' in the firewall chain \'OUTPUT\' is not '
                       'unique on node \'node1\''
            },
            {
                'url': cluster_fw_rule_tc17_2_url,
                'msg': 'ValidationError    Create plan failed: Position '
                       '\'173\' in the firewall chain \'INPUT\' is not '
                       'unique on node \'node1\''
            },
            {
                'url': cluster_fw_rule_tc17_2_url,
                'msg': 'ValidationError    Create plan failed: Position '
                       '\'173\' in the firewall chain \'OUTPUT\' is not '
                       'unique on node \'node1\''
            },
            {
                'url': cluster_fw_rule_tc17_1_url,
                'msg': 'ValidationError    Create plan failed: Position '
                       '\'173\' in the firewall chain \'INPUT\' is not '
                       'unique on node \'node2\''
            },
            {
                'url': cluster_fw_rule_tc17_1_url,
                'msg': 'ValidationError    Create plan failed: Position '
                       '\'173\' in the firewall chain \'OUTPUT\' is not '
                       'unique on node \'node2\''
            },
            {
                'url': cluster_fw_rule_tc17_2_url,
                'msg': 'ValidationError    Create plan failed: Position '
                       '\'173\' in the firewall chain \'INPUT\' is not '
                       'unique on node \'node2\''
            },
            {
                'url': cluster_fw_rule_tc17_2_url,
                'msg': 'ValidationError    Create plan failed: Position '
                       '\'173\' in the firewall chain \'OUTPUT\' is not '
                       'unique on node \'node2\''
            }
        ]

        self.execute_cli_createplan_cmd(self.ms1)

        self.execute_cli_update_cmd(self.ms1,
                                    cluster_fw_rule_tc17_2_url,
                                    "name='173 test17c 1'")

        _, stderr, _ = self.execute_cli_createplan_cmd(self.ms1,
                                                       expect_positive=False)

        missing, extra = self._check_cli_errors(expected_errors, stderr)
        self.assertEqual([], missing,
            '\nMISSING ERRORS:\n{0}'.format('\n'.join(missing)))
        self.assertEqual([], extra,
            '\nEXTRA ERRORS:\n{0}'.format('\n'.join(extra)))

        self.execute_cli_remove_cmd(self.ms1, cluster_fw_rule_tc17_1_url)
        self.execute_cli_remove_cmd(self.ms1, cluster_fw_rule_tc17_2_url)

        self.log('info',
        'x. Cluster level rule and a node level rule cannot have the same '
            'chain order')
        cluster_fw_rule_url = cluster_fw_config_url + "/rules/fw0024"
        self.execute_cli_create_cmd(self.ms1,
                                    cluster_fw_rule_url,
                                    "firewall-rule",
                                    "name='176 test17'")

        node_fw_config_url = self._create_fw_config("mynodefwconfig",
                                                    cluster_config=False)
        node_fw_rule_url = self._create_fw_rule_item(node_fw_config_url,
                                                     "fw0025",
                                                     "name='178 test17'")

        self.execute_cli_update_cmd(self.ms1,
                                    node_fw_rule_url,
                                    "name='176 test17'")

        expected_errors = [
            {
                'url': cluster_fw_rule_url,
                'msg': 'ValidationError    Create plan failed: Position '
                       '\'176\' in the firewall chain \'INPUT\' is not '
                       'unique on node \'node1\''
            },
            {
                'url': cluster_fw_rule_url,
                'msg': 'ValidationError    Create plan failed: Position '
                       '\'176\' in the firewall chain \'OUTPUT\' is not '
                       'unique on node \'node1\''
            },
            {
                'url': node_fw_rule_url,
                'msg': 'ValidationError    Create plan failed: Position '
                       '\'176\' in the firewall chain \'INPUT\' is not '
                       'unique on node \'node1\''
            },
            {
                'url': node_fw_rule_url,
                'msg': 'ValidationError    Create plan failed: Position '
                       '\'176\' in the firewall chain \'OUTPUT\' is not '
                       'unique on node \'node1\''
            }
        ]

        _, stderr, _ = self.execute_cli_createplan_cmd(self.ms1,
                                                       expect_positive=False)

        missing, extra = self._check_cli_errors(expected_errors, stderr)
        self.assertEqual([], missing,
            '\nMISSING ERRORS:\n{0}'.format('\n'.join(missing)))
        self.assertEqual([], extra,
            '\nEXTRA ERRORS:\n{0}'.format('\n'.join(extra)))

    #@attr('pre-reg', 'revert', 'cdb_priority1', 'story2076', 'story2076_tc18')
    def obsolete_18_p_update_firewall_rules(self):
        """
        Obsoleted as functionality moved to test_02_p_create_rules and
        test_03_p_update_remove_rules in testset_firewall_rule_positive.py

        @#tms_id: litpcds_2076_tc18
        @#tms_requirements_id: LITPCDS-2076
        @#tms_title: Firewall rules and litp update
        @#tms_description: Test valid updates validation including
            rule deployment to nodes
        @#tms_test_steps:
            @step: Create cluster level firewall rules
            @result: Rules are created in litp model
            @step: Create & run plan is run successfully
            @result: Rules are created at cluster level
            @step: Check the tables contain the expected rule
            @result: iptables contain the expected rule
            @step: Create a plan to update firewall rules
            @result: Plan is run successfully
            @result: Rules are updated at cluster level
            @result: Iptables contain the expected rule
        @#tms_test_precondition:NA
        @#tms_execution_type: Automated
        """
        # 1. Find firewall cluster config already in model
        fw_cluster_config = self.find(
            self.ms1, "/deployments", "firewall-cluster-config")[0]

        # 2. Define cluster level firewall rules
        # rule1:
        props = ('name="181 test18a" sport="1123" table="mangle" jump="LOG"'
                 ' chain="OUTPUT" dport="233-5657"')
        self._create_fw_rule_item(
            fw_cluster_config, "fw018rule01", props)

        # rule2:
        props = ('name="182 test18b" source="10.10.01.0/24" iniface="lo"'
                 ' destination="10.10.10.5-10.10.10.10" provider="iptables"')
        self._create_fw_rule_item(
            fw_cluster_config, "fw018rule02", props)

        # rule3:
        props = ('name="183 test18c"'
                 ' log_level="warning" log_prefix="valid" jump="LOG"')
        self._create_fw_rule_item(
            fw_cluster_config, "fw018rule03", props)

        # rule4:
        props = ('name="184 test18d"'
                 ' sport="22" table="mangle" jump="DSCP"'
                 ' setdscp="0x10" chain="OUTPUT" provider="ip6tables"'
                 ' outiface="2"')
        self._create_fw_rule_item(
            fw_cluster_config, "fw018rule04", props)

        # rule5:
        props = ('name="185 test18e" provider="iptables"'
                 ' log_level="warning" jump="LOG"')
        self._create_fw_rule_item(
            fw_cluster_config, "fw018rule05", props)

        # 3.Create plan
        self.execute_cli_createplan_cmd(self.ms1)

        # 4.Run plan
        self.execute_cli_runplan_cmd(self.ms1)

        # Wait for plan to complete
        self.assertTrue(self.wait_for_plan_state(
            self.ms1, test_constants.PLAN_COMPLETE))

        # 5. Check the tables contain the expected rules
        for node in self.test_nodes:
            # check rule1 had been added in iptables and in ip6tables
            self._assert_iptables_rule(
                node, ['-A OUTPUT', '-p tcp',
                       '--sport 1123',
                       '-m multiport', '--dports 233:5657',
                       '-m comment',
                       '--comment "1181 test18a ipv4"',
                       '-m state', '--state NEW',
                       '-j LOG'],
                "POSTROUTING")
            self._assert_iptables_rule_v6(
                node, ['-A OUTPUT', '-p tcp',
                       '--sport 1123',
                       '-m multiport', '--dports 233:5657',
                       '-m comment',
                       '--comment "1181 test18a ipv6"',
                       '-m state', '--state NEW',
                       '-j LOG'],
                "POSTROUTING")
            # check rule2 has been created in iptables with expected parameters
            self._assert_iptables_rule(
                node, [
                    '-A INPUT', '-s 10.10.1.0/24', '-i lo', '-p tcp',
                    '-m iprange', '--dst-range 10.10.10.5-10.10.10.10',
                    '-m comment', '--comment "182 test18b ipv4"',
                    '-j ACCEPT'],
                "OUTPUT")
            # check rule3 has been created in iptables and ip6tables
            # with expected parameters
            self._assert_iptables_rule(
                node, [
                    '-A INPUT', '-p tcp', '-m comment',
                    '--comment "183 test18c ipv4"', '-j LOG',
                    '--log-prefix "valid"'],
                "OUTPUT")
            self._assert_iptables_rule_v6(
                node, [
                    '-A INPUT', '-p tcp', '-m comment',
                    '--comment "183 test18c ipv6"', '-j LOG',
                    '--log-prefix "valid"'],
                "OUTPUT")
            # check rule4 has been created in ip6tables with
            # expected parameters
            self._assert_iptables_rule_v6(
                node, ['-A OUTPUT', '-o 2', '-p tcp',
                       '--sport 22',
                       '-m comment',
                       '--comment "1184 test18d ipv6"',
                       '-m state', '--state NEW',
                       '-j DSCP', '--set-dscp 0x10'],
                "POSTROUTING")
            # check rule5 has been created in iptables
            # with expected parameters
            self._assert_iptables_rule(
                node, [
                    '-A INPUT', '-p tcp', '-m comment',
                    '--comment "185 test18e ipv4"', '-j LOG'],
                "OUTPUT")

        # 6a. Update rule1:
        # Update firewall rule name from 0181 test18a to 0181 test18 fw1a
        # Update proto from default value to "udp"
        # Update sport from a single value "1123" to a range, "233-676"
        # Update dport from a range, 233-5657 to a single value, "677"
        # Update state from a single value, "NEW" to a list of
        # comma seperated vlaues, "NEW,ESTABLISHED,RELATED"
        # Update table value from "mangle" to "filter"
        # Update provider from none(present both tables) to iptables
        props = ('name="181 test18 fw1a" provider="iptables"'
                 ' proto="udp" sport="233-676"'
                 ' dport="677" state="NEW,ESTABLISHED,RELATED" table="filter"')

        self._update_fw_rule_props_list(
            fw_cluster_config, "fw018rule01", props)

        # 6b. Update rule2:
        # Update action from accept to drop
        # Update source from a ip address subnets to an IP address range
        # Update destination from an IP address range to a single IP address
        # Update chain from none to INPUT
        # Update iniface from string to number
        props = ('source="10.10.10.5-10.10.10.10" action="drop" iniface="3"'
                 ' destination="129.167.122.99" chain="INPUT"')

        self._update_fw_rule_props_list(
            fw_cluster_config, "fw018rule02", props)

        # 6c. Update rule3:
        # Update provider from none(present in both tables) to ip6tables,
        # Update log_level value
        # Update log_prefix value

        props = ('provider="ip6tables" log_level="debug"'
                 ' log_prefix="valid_testing"')

        self._update_fw_rule_props_list(
            fw_cluster_config, "fw018rule03", props)

        # 6d. Update rule4:
        # Update provider from iptables to none(present in both tables)
        # Update setdscp value
        # Update outiface from number to string
        props = ('provider')
        self._update_fw_rule_remove_props_list(
            fw_cluster_config, "fw018rule04", props)

        props = ('setdscp="0x20" outiface="lo"')

        self._update_fw_rule_props_list(
            fw_cluster_config, "fw018rule04", props)

        # 6e. Update rule5:
        # Update log_prefix value
        props = ('log_prefix="valid_testing"')
        self._update_fw_rule_props_list(
            fw_cluster_config, "fw018rule05", props)

        # Update rule to remove property
        # Update provider from iptables to none, i.e. the rule exist in
        #  iptables and ip6tables
        props = ('log_level,provider')
        self._update_fw_rule_remove_props_list(
            fw_cluster_config, "fw018rule05", props)

        # 7. Create plan
        self.execute_cli_createplan_cmd(self.ms1)

        # 8. Run plan
        self.execute_cli_runplan_cmd(self.ms1)

        # Wait for plan to complete
        self.assertTrue(self.wait_for_plan_state(
            self.ms1, test_constants.PLAN_COMPLETE))

        # 9. Check tables contain correct rules
        cmd_to_run = \
             "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l".format(
              self.IP_TABLES, self.OUTPUT, "test18 fw1a ipv4")
        self.assertTrue(self.wait_for_puppet_action(
            self.ms1, self.test_nodes[0], cmd_to_run, 0, "1", True))

        for node in self.test_nodes:
            # check rule1 updated in iptables with expected parameters
            self._assert_iptables_rule(
                node, ['-A OUTPUT', '-p udp',
                       '-m multiport', '--sports 233:676',
                       '--dport 677',
                       '-m comment',
                       '--comment "1181 test18 fw1a ipv4"',
                       '-m state', '--state NEW,RELATED,ESTABLISHED',
                       '-j LOG'],
                "OUTPUT")
            # check rule1 no longer present on ip6tables
            cmd_to_run = \
                 "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l".format(
                  self.IP6_TABLES, self.INPUT, "0181")
            self.assertTrue(self.wait_for_puppet_action(
                self.ms1, node, cmd_to_run, 0, "0", True))

            # check rule2 updated with expected parameters
            self._assert_iptables_rule(
                node, [
                    '-A INPUT', '-d 129.167.122.99/32', '-i 3', '-p tcp',
                    '-m iprange', '--src-range 10.10.10.5-10.10.10.10',
                    '-m comment', '--comment "182 test18b ipv4"', '-j DROP'],
                "OUTPUT")
            # check rule2 is nolonger exists in the OUTPUT chain
            # in iptables
            cmd_to_run = \
                 "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l".format(
                  self.IP_TABLES, self.OUTPUT, "0182")
            self.assertTrue(self.wait_for_puppet_action
                   (self.ms1, node, cmd_to_run, 0, "0", True))

            # check rule3 updated in ip6tables with given parameters
            self._assert_iptables_rule_v6(
                node, [
                    '-A INPUT', '-p tcp', '-m comment',
                    '--comment "183 test18c ipv6"', '-j LOG',
                    '--log-prefix "valid_testing"', '--log-level 7'],
                "OUTPUT")
            # check rule3 is nolonger exists in the iptables
            cmd_to_run = \
                 "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l".format(
                  self.IP_TABLES, self.INPUT, "0183")
            self.assertTrue(self.wait_for_puppet_action
                   (self.ms1, node, cmd_to_run, 0, "0", True))

            # check rule4 updated in ip6tables and iptables
            # with expected parameters
            self._assert_iptables_rule_v6(
                node, ['-A OUTPUT', '-o lo', '-p tcp',
                       '--sport 22',
                       '-m comment',
                       '--comment "1184 test18d ipv6"',
                       '-m state', '--state NEW',
                       '-j DSCP', '--set-dscp 0x20'],
                "POSTROUTING")
            self._assert_iptables_rule(
                node, ['-A OUTPUT', '-o lo', '-p tcp',
                       '--sport 22',
                       '-m comment',
                       '--comment "1184 test18d ipv4"',
                       '-m state', '--state NEW',
                       '-j DSCP', '--set-dscp 0x20'],
                "POSTROUTING")

            # check rule5 present in both tables with expected parameters
            self._assert_iptables_rule(
                node, [
                    '-A INPUT', '-p tcp', '-m comment',
                    '--comment "185 test18e ipv4"', '-j LOG',
                    '--log-prefix "valid_testing"'],
                "OUTPUT")
            self._assert_iptables_rule_v6(
                node, [
                    '-A INPUT', '-p tcp', '-m comment',
                    '--comment "185 test18e ipv6"', '-j LOG',
                    '--log-prefix "valid_testing"'],
                "OUTPUT")

    #@attr('pre-reg', 'revert', 'story2076', 'story2076_tc19')
    def obsolete_19_n_remove_firewall_rule(self):
        """
        Obsoleted as functionality moved to ATs:
            ERIClitplinuxfirewall:
                test_19_n_remove_firewall_rule.at

        @#tms_id: litpcds_2076_tc19
        @#tms_requirements_id: LITPCDS-2076
        @#tms_title: Remove firewall rule
        @#tms_description: Test negative scenario at removal of a firewall rule
        @#tms_test_steps:
            @step: Create cluster level firewall rule with parameters provided
            @result: Rules are created in litp model
            @step: Create plan & run plan
            @result: Rule are created at cluster level
            @step: Remove an non-existant rule
            @result: Command fails with expected message
            @step: Remove rule cluster level firewall rule
            @result: Rule is now has state set to "ForRemoval"
            @step: Attempt to remove rule already marked, "ForRemoval"
            @result: Command is successful
        @#tms_test_precondition:NA
        @#tms_execution_type: Automated
        """
        # Find firewall cluster config already in model
        fw_cluster_config = self.find(
            self.ms1, "/deployments", "firewall-cluster-config")[0]

        # Define cluster level firewall rule with all parameters provided
        props = ('name="190 test19" proto="tcp" action="accept" sport="1123"'
                 ' dport="655" state="NEW" source="129.167.122.99"'
                 ' destination="129.167.122.99" '
                 ' provider="iptables"')
        firewall_rule1 = self._create_fw_rule_item(
            fw_cluster_config, "fw019", props)

        # Create plan
        self.execute_cli_createplan_cmd(self.ms1)

        # Run plan
        self.execute_cli_runplan_cmd(self.ms1)

        # Wait for plan to complete
        self.assertTrue(self.wait_for_plan_state(
            self.ms1, test_constants.PLAN_COMPLETE))

        # Remove an non-existant rule
        firewall_rule2 = fw_cluster_config + "/rules/fw19a"

        expected_errors = [
            {
                'url': firewall_rule2,
                'msg': 'InvalidLocationError    Path not found'
            }
        ]

        _, stderr, _ = self.execute_cli_remove_cmd(self.ms1,
                                                   firewall_rule2,
                                                   expect_positive=False)

        missing, extra = self._check_cli_errors(expected_errors, stderr)
        self.assertEqual([], missing,
            '\nMISSING ERRORS:\n{0}'.format('\n'.join(missing)))
        self.assertEqual([], extra,
            '\nEXTRA ERRORS:\n{0}'.format('\n'.join(extra)))

        # Set state to "ForRemoval"
        self._remove_fw_rule(fw_cluster_config, "fw019")

        # Check state
        state_value = self.execute_show_data_cmd(self.ms1,
                                                 firewall_rule1, "state")
        self.assertEqual(state_value, "ForRemoval")

        # Attempt to remove rule already marked, "ForRemoval"
        self._remove_fw_rule(fw_cluster_config, "fw019")

    #@attr('pre-reg', 'revert', 'story2076', 'story2076_tc20')
    def obsolete_20_p_import_updated_firewall_rules(self):
        """
        Obsoleted as functionality moved to test_01_p_load_rules_from_XML
            in testset_firewall_load_rules_xml.py

        @#tms_id: litpcds_2076_tc20
        @#tms_requirements_id: LITPCDS-2076
        @#tms_title: Import updated firewall rules
        @#tms_description: Test import of an XML file containing
            updated properties
        @#tms_test_steps:
            @step: Load an XML files containing 3 cluster level firewall rules
            @result: XML file is loaded successfully in litp
            @step: Create plan & Run plan
            @result: Cluster level firewall rules created
            @step: Load XML files that add, update & removes firewall rules
            @result: XML files are loaded successfully in litp
            @step: Create plan & Run plan
            @result: Rules updated as expected on nodes
            @step: Remove loaded firewall rules
            @result: Rules are removed
        @#tms_test_precondition:NA
        @#tms_execution_type: Automated
        """
        # System must have at least 2 nodes to continue
        nodes_path = self.find(self.ms1, "/deployments", "node", True)
        self.assertTrue(
            len(nodes_path) > 1,
            "The LITP Tree has less than 2 nodes defined")
        node1_path = nodes_path[0]
        node2_path = nodes_path[1]
        test_node1 = self.get_node_filename_from_url(self.ms1, node1_path)
        test_node2 = self.get_node_filename_from_url(self.ms1, node2_path)

        # 1. Copy prepared xml files onto the MS
        xml_filenames = \
            ['xml_cluster_fw_rules_1_story2076.xml',
             'xml_cluster_fw_rules_2_story2076.xml',
             'xml_n1_fw_rules_story2076.xml', 'xml_n2_fw_rules_story2076.xml']
        local_filepath = os.path.dirname(__file__)
        for xml_filename in xml_filenames:
            local_xml_filepath = local_filepath + "/xml_files/" + xml_filename
            xml_filepath = "/tmp/" + xml_filename
            self.assertTrue(self.copy_file_to(
                self.ms1, local_xml_filepath, xml_filepath,
                root_copy=True))

        # Find cluster level config rules path
        cluster_config_rule_path = self.find(
            self.ms1, "/deployments",
            "firewall-cluster-config")[0]

        # Find node1 level config rules path
        n1_config_rule_path = self.find(
            self.ms1, node1_path,
            "firewall-node-config")[0]

        # Find node2 level config rules path
        n2_config_rule_path = self.find(
            self.ms1, node2_path,
            "firewall-node-config")[0]

        try:
            # 2. Load an XML file containing 3 cluster level firewall rules
            #    using the --merge option

            self.execute_cli_load_cmd(
                self.ms1, cluster_config_rule_path,
                "/tmp/xml_cluster_fw_rules_1_story2076.xml", "--merge")

            # 3. Create plan
            self.execute_cli_createplan_cmd(self.ms1)

            # 4. Run plan
            self.execute_cli_runplan_cmd(self.ms1)

            # Wait for plan to complete
            self.assertTrue(self.wait_for_plan_state(
                self.ms1, test_constants.PLAN_COMPLETE))

            # 5. Check rules have been created:
            for node in self.test_nodes:
                self._assert_iptables_rule(
                    node, [
                        '-A INPUT', '-s 129.167.122.99/32',
                        '-d 129.167.122.99/32',
                        '-p tcp', '--sport 1123',
                        '--dport 65531', '-m comment',
                        '--comment "201 test20 ipv4"',
                        '-m state', '--state NEW', '-j ACCEPT'],
                    "OUTPUT")
                self._assert_iptables_rule(
                    node, [
                          '-A INPUT', '-p udp', '-m iprange',
                          '--src-range 10.45.239.84-10.45.239.85',
                          '-m iprange',
                          ' --dst-range 10.45.239.85-10.45.239.87',
                          '-m multiport', '--dports 30000:65000',
                          '-m comment', '--comment "077 test20b ipv4"',
                          '-m state', '--state NEW', '-j ACCEPT'],
                    "OUTPUT")
                self._assert_iptables_rule(
                    node, [
                          '-A PREROUTING', '-p udp', '-m iprange',
                          '--src-range 10.45.239.84-10.45.239.85',
                          '-m iprange',
                          '--dst-range 10.45.239.85-10.45.239.87',
                          '--dport 162', '-m comment',
                          '--comment "076 test20a ipv4"',
                          ' -m state', '--state NEW',
                          '-j REDIRECT', '--to-ports 30162'],
                    "OUTPUT")

            # 6. Load an XML file that removes 2 cluster level firewall rules
            #   using the --replace option
            self.execute_cli_load_cmd(
                self.ms1, cluster_config_rule_path,
                "/tmp/xml_cluster_fw_rules_2_story2076.xml", "--replace")

            # 7. Load an XML file that adds one of the removed cluster level
            #    firewall rules that has been updated onto node1 and the other
            #    removed cluster level firewall rule that has been split using
            #    --merge option
            self.execute_cli_load_cmd(
                self.ms1, n1_config_rule_path,
                "/tmp/xml_n1_fw_rules_story2076.xml", "--merge")

            # 8. Load an XML file that adds the removed cluster level
            #    firewall rule that has been split onto node2
            #    using --merge option
            self.execute_cli_load_cmd(
                self.ms1, n2_config_rule_path,
                "/tmp/xml_n2_fw_rules_story2076.xml", "--merge")

            # 9. Create plan
            self.execute_cli_createplan_cmd(self.ms1)

            # 10. Run plan
            self.execute_cli_runplan_cmd(self.ms1)

            # Wait for plan to complete
            self.assertTrue(self.wait_for_plan_state(
                self.ms1, test_constants.PLAN_COMPLETE))

            # 11.Check correct firewall rules in tables
            for node in self.test_nodes:
                # Check rule20 is still present in iptables
                self._assert_iptables_rule(
                    node, [
                        '-A INPUT', '-s 129.167.122.99/32',
                        '-d 129.167.122.99/32',
                        '-p tcp',
                        '--sport 1123',
                        '--dport 65531', '-m comment',
                        '--comment "201 test20 ipv4"',
                        '-m state', '--state NEW',
                        '-j ACCEPT'],
                    "OUTPUT")

                # Check rules test20a and test20b have been removed
                # by the replace command from iptables
                cmd_to_run = \
                 "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l".format(
                 self.IP_TABLES, self.INPUT, "076 test20a")
                self.assertTrue(self.wait_for_puppet_action(
                    self.ms1, node, cmd_to_run, 0, "0", True))
                cmd_to_run = \
                 "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l".format(
                 self.IP_TABLES, self.INPUT, "077 test20b")
                self.assertTrue(self.wait_for_puppet_action(
                    self.ms1, node, cmd_to_run, 0, "0", True))

            # Check rules test20e and test20d have been added
            # to iptables on node1
            self._assert_iptables_rule(
                    test_node1, [
                          '-A PREROUTING', '-p udp', '-m iprange',
                          '--src-range 10.45.239.84-10.45.239.85',
                          '-m iprange',
                          '--dst-range 10.45.239.85-10.45.239.87',
                          '--dport 162', '-m comment',
                          '--comment "070 test20e ipv4"',
                          ' -m state', '--state NEW',
                          '-j REDIRECT',
                          '--to-ports 30162'],
                    "OUTPUT")
            self._assert_iptables_rule(
                    test_node1, [
                          '-A INPUT', '-p udp', '-m iprange',
                          '--src-range 10.45.239.84-10.45.239.85',
                          '-m iprange',
                          ' --dst-range 10.45.239.85-10.45.239.86',
                          '-m multiport',
                          '--dports 30000:65000', '-m comment',
                          '--comment "079 test20d ipv4"',
                          '-m state', '--state NEW', '-j ACCEPT'],
                    "OUTPUT")

            # Check rule test20c has been added to iptables on node2
            self._assert_iptables_rule(
                    test_node2, [
                          'A OUTPUT', '-s 10.45.239.85/32',
                          '-d 10.45.239.87/32',
                          '-p udp', '-m multiport',
                          '--dports 30000:65000',
                          '-m comment', '--comment "1078 test20c ipv4"',
                          '-m state',
                          '--state NEW', '-j ACCEPT'],
                    "OUTPUT")

        finally:
            # 12. Remove loaded firewall rules
            # Remove imported items
            # Define list
            del_rm_list = []
            root_url, _, _ = self.execute_cli_show_cmd(
                self.ms1, "/", args='-rl')
            for url in root_url:
                if "2076" in url:
                    del_rm_list.append(self.cli.get_remove_cmd(url))

            self.run_commands(self.ms1, del_rm_list)

    #@attr('pre-reg', 'revert', 'story2076', 'story2076_tc21')
    def obs_21_p_create_firewall_rules_purges_manually_added_rules(self):
        """
        Obsoleted as functionality moved to test_02_p_create_rules
            in testset_firewall_rule_positive.py

        Description:
            @#tms_id: litpcds_2076_tc21
            @#tms_requirements_id: LITPCDS-2076
            @#tms_title: Create firewall rules purges manually added rules
            @#tms_description: Test that manually created firewall rules are
                removed when puppet agent runs on nodes
            @#tms_test_steps:
                @step: Add firewall rules manually to iptables/ip6tables
                @result: Rules manually added iptables/ip6tables
                @step: Create cluster level firewall rule LITP items
                @result: Cluster level firewall rule LITP items are created
                @step: Check that iptables contains rules created with LITP
                @result: Iptables contains rules created with LITP
                @step: Check that manual rules are removed
                @result: Manual rules are removed
            @#tms_test_precondition:NA
            @#tms_execution_type: Automated
        """
        all_nodes = [self.mn1, self.mn2]
        all_providers = [self.IP_TABLES, self.IP6_TABLES]
        all_tables = ['filter', 'raw', 'mangle', 'nat']

        # Each rule created manually is removed at next puppet run
        # It is possible that a rule manually created is removed before we
        # have the chance to check for it. Instead of failing right away we
        # retry a number of times.
        # After 5 attempts to find the rules created manually on iptables we
        # fail
        for index in range(1, 6):
            self.log('info',
            '1.{0} Add firewall rules manually to iptables/ip6tables'.
            format(index, format_spec=None))
            self._get_iptables_configuration(all_nodes,
                                             all_providers,
                                             all_tables)

            node1 = self.test_nodes[0]
            ipv4_add = '207.52.75.3'
            ipv6_add = '1:2:3:4:5:6:7:cafb'

            cmd = '/sbin/iptables -A INPUT -s {0} -j DROP'.format(ipv4_add)
            self.run_command(node1, cmd, su_root=True, default_asserts=True)

            cmd = '/sbin/ip6tables -A INPUT -s {0} -j DROP'.format(ipv6_add)
            self.run_command(node1, cmd, su_root=True, default_asserts=True)

            self.log('info',
            '2.{0} Check that the rules created manually are on '
               'iptables/ip6tables'.format(index))
            self._get_iptables_configuration(all_nodes,
                                             all_providers,
                                             all_tables)

            ipv4_rules = self._check_iptables(node1,
                                              ipv4_add,
                                              ip_tables=self.IP_TABLES,
                                              inout=self.INPUT,
                                              assert_result=False)

            ipv6_rules = self._check_iptables(node1,
                                              ipv6_add,
                                              ip_tables=self.IP6_TABLES,
                                              inout=self.INPUT,
                                              assert_result=False)

            if len([x for x in ipv4_rules if x != '0']) > 0 and \
               len([x for x in ipv6_rules if x != '0']) > 0:
                break
        else:
            self.fail('Failed to find rules created manually on iptables')

        self.log('info',
        '3. Create cluster level firewall rule LITP items and run the '
           'plan to trigger a "puppet agent run" on each node')
        fw_cluster_config = self.find(
                    self.ms1, "/deployments", "firewall-cluster-config")[0]

        self._create_fw_rule_props_by_kw(
                    fw_cluster_config, "fw001", name='"210 test21"')

        self.execute_cli_createplan_cmd(self.ms1)
        self.execute_cli_runplan_cmd(self.ms1)
        self.assertTrue(self.wait_for_plan_state(self.ms1,
                                                test_constants.PLAN_COMPLETE))

        self.log('info',
        '4. Check that iptables contains rules created with LITP')
        self._get_iptables_configuration(all_nodes, all_providers, all_tables)

        for node in self.test_nodes:
            self._check_iptables(node, '"210 test21"')

        self.log('info',
        '5. Check that manual rules are removed')
        cmd = ("/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l".
              format(self.IP_TABLES, self.INPUT, ipv4_add))
        std_out, _, _ = self.run_command(node1, cmd,
                                         su_root=True, default_asserts=True)
        self.assertTrue(self.is_text_in_list("0", std_out), std_out)

        cmd = ("/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l".
              format(self.IP6_TABLES, self.INPUT, ipv6_add))
        std_out, _, _ = self.run_command(node1, cmd,
                                         su_root=True, default_asserts=True)
        self.assertTrue(self.is_text_in_list("0", std_out), std_out)

    #@attr('pre-reg', 'revert', 'story2076', 'story2076_tc22')
    def obsolete_22_p_remove_firewall_config(self):
        """
        Obsoleted as functionality moved to test_01_p_load_rules_from_XML
            in testset_firewall_load_rules_xml.py

        @#tms_id: litpcds_2076_tc22
        @#tms_requirements_id: LITPCDS-2076
        @#tms_title: Remove firewall config
        @#tms_description: Test that if the firewall cluster config is removed,
            and there are no node level firewall configs present, the
            iptables and ip6tables are empty and a node level firewall config
            with rules can be created
        @#tms_test_steps:
            @step: Export existing cluster and node firewall config
            @result: Items are exported successfully to files
            @step: Create plan to remove existing firewall items at cluster
                and node level
            @result: Plan is run successfully
            @result: Firewall rules are removed successfully
            @step: Check iptables and ip6tables are empty
            @result: Rules are as expected
            @step: Load exported node2 firewall xml snippet
            @result: XML file is loaded successfully
            @step: Create plan & Run plan
            @result: Plan is run successfully
            @step: Load the remaining exported firewall xml snippets
            @result: XML file is loaded successfully
            @step: Create plan & Run plan
            @result: Plan is run successfully
        @#tms_test_precondition:NA
        @#tms_execution_type: Automated
        """
        # System must have at least 2 nodes to continue
        nodes_path = self.find(self.ms1, "/deployments", "node", True)
        self.assertTrue(
            len(nodes_path) > 1,
            "The LITP Tree has less than 2 nodes defined")
        node1_path = nodes_path[0]
        node2_path = nodes_path[1]

        # 1. Find cluster level config path
        cluster_config_path = self.find(
            self.ms1, "/deployments",
            "collection-of-cluster-config")[0]

        # 2. Find cluster level firewall config path
        cluster_config_rule_path = self.find(
            self.ms1, "/deployments",
            "firewall-cluster-config")[0]

        # 3. Export existing cluster firewall config
        self.execute_cli_export_cmd(
            self.ms1, cluster_config_rule_path,
            "/tmp/xml_22_c1config_story2076.xml")

        # 4. Find node1 config path
        n1_config_path = self.find(
            self.ms1, node1_path, "collection-of-node-config")[0]

        # 5. Find node1 firewall config path
        n1_node_config = self.find(
            self.ms1, node1_path,
            "firewall-node-config")[0]

        # 6. Export existing node1 firewall config
        self.execute_cli_export_cmd(
            self.ms1, n1_node_config, "/tmp/xml_22_n1config_story2076.xml")

        # 7. Find node2 config path
        n2_config_path = self.find(
            self.ms1, node2_path, "collection-of-node-config")[0]

        # 8. Find node2 firewall config path
        n2_node_config = self.find(
            self.ms1, node2_path,
            "firewall-node-config")[0]

        # 9. Export existing node2 firewall config
        self.execute_cli_export_cmd(
            self.ms1, n2_node_config, "/tmp/xml_22_n2config_story2076.xml")

        try:
            # 10.Remove existing firewall items at cluster and node level
            self.execute_cli_remove_cmd(self.ms1, cluster_config_rule_path)
            self.execute_cli_remove_cmd(self.ms1, n1_node_config)
            self.execute_cli_remove_cmd(self.ms1, n2_node_config)

            # 11.Create plan
            self.execute_cli_createplan_cmd(self.ms1)

            # 12.Run plan
            self.execute_cli_runplan_cmd(self.ms1)

            # 13.Wait for plan to complete
            self.assertTrue(self.wait_for_plan_state(
                self.ms1, test_constants.PLAN_COMPLETE))

            # 14.Check iptables and ip6tables are empty
            for node in self.test_nodes:
                std_out, std_err, rc = self.run_command(
                    node,
                    "/sbin/iptables -L -n",
                    su_root=True)
                self.assertEquals([], std_err)
                self.assertEquals(0, rc)
                self.assertEqual(len(std_out), 6)

                std_out, std_err, rc = self.run_command(
                    node,
                    "/sbin/ip6tables -L -n",
                    su_root=True)
                self.assertEquals([], std_err)
                self.assertEquals(0, rc)
                self.assertEqual(len(std_out), 6)

                cmd_to_run = \
                 "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l".format(
                 self.IP_TABLES, self.INPUT, "'999 drop all'")
                self.assertTrue(self.wait_for_puppet_action
                       (self.ms1, node, cmd_to_run, 0, "0", True))

                cmd_to_run = \
                 "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l".format(
                 self.IP_TABLES, self.OUTPUT, "'1999 drop all'")
                self.assertTrue(self.wait_for_puppet_action
                       (self.ms1, node, cmd_to_run, 0, "0", True))

                cmd_to_run = \
                 "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l".format(
                 self.IP6_TABLES, self.INPUT, "'999 drop all v6'")
                self.assertTrue(self.wait_for_puppet_action
                       (self.ms1, node, cmd_to_run, 0, "0", True))

                cmd_to_run = \
                 "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l".format(
                 self.IP6_TABLES, self.OUTPUT, "'1999 drop all v6'")
                self.assertTrue(self.wait_for_puppet_action
                       (self.ms1, node, cmd_to_run, 0, "0", True))

        finally:
            # 15.Load exported node2 firewall xml snippet
            self.execute_cli_load_cmd(
                    self.ms1, n2_config_path,
                    "/tmp/xml_22_n2config_story2076.xml",
                    "--replace")

            # 16.Create plan
            self.execute_cli_createplan_cmd(self.ms1)

            # 17.Run plan
            self.execute_cli_runplan_cmd(self.ms1)

            # 18.Wait for plan to complete
            self.assertTrue(self.wait_for_plan_state(
                self.ms1, test_constants.PLAN_COMPLETE))

            # 19.Load the remaining exported firewall xml snippets
            self.execute_cli_load_cmd(
                    self.ms1, cluster_config_path,
                    "/tmp/xml_22_c1config_story2076.xml",
                    "--replace")

            self.execute_cli_load_cmd(
                    self.ms1, n1_config_path,
                    "/tmp/xml_22_n1config_story2076.xml",
                    "--replace")

            # 20.Create plan
            self.execute_cli_createplan_cmd(self.ms1)

            # 21.Run plan
            self.execute_cli_runplan_cmd(self.ms1)

            # 22.Wait for plan to complete
            self.assertTrue(self.wait_for_plan_state(
                self.ms1, test_constants.PLAN_COMPLETE))

    #@attr('pre-reg', 'revert', 'story2076', 'story2076_tc23')
    def obsolete_23_p_remove_firewall_node_config(self):
        """
        Obsoleted as functionality moved to test_01_p_load_rules_from_XML
            in testset_firewall_load_rules_xml.py

        @#tms_id: litpcds_2076_tc23
        @#tms_requirements_id: LITPCDS-2076
        @#tms_title: Remove firewall node config
        @#tms_description: Test that if the firewall node config is deleted,
            the node level rules are removed from the iptables and ip6tables
        @#tms_test_steps:
            @step: Export node firewall-node-configs
            @result: Item are exported successfully
            @step: Remove firewall node configs & Create & run Plan
            @result: node config rules are removed but
                cluster level rule are still present
            @step: Load exported firewall node configs
            @result: XML file is loaded successfully in litp
            @step: Create plan & Run plan
            @result: Plan is run successfully
        @#tms_test_precondition:NA
        @#tms_execution_type: Automated
        """
        # System must have at least 2 nodes to continue
        nodes_path = self.find(self.ms1, "/deployments", "node", True)
        self.assertTrue(
            len(nodes_path) > 1,
            "The LITP Tree has less than 2 nodes defined")
        node1_path = nodes_path[0]
        node2_path = nodes_path[1]

        # Find cluster level config rules path
        cluster_config_path = self.find(
            self.ms1, "/deployments",
            "collection-of-cluster-config")[0]

        # Find cluster level config rules path
        cluster_config_rule_path = self.find(
            self.ms1, "/deployments",
            "firewall-cluster-config")[0]

        # Export existing cluster firewall config
        self.execute_cli_export_cmd(
            self.ms1, cluster_config_rule_path,
            "/tmp/xml_23_c1config_story2076.xml")

        # Find node1 config path
        n1_config_path = self.find(
            self.ms1, node1_path, "collection-of-node-config")[0]

        # Find node1 firewall node config path
        n1_node_config = self.find(
            self.ms1, node1_path,
            "firewall-node-config")[0]

        # 1. Export node1 firewall node config
        self.execute_cli_export_cmd(
            self.ms1, n1_node_config, "/tmp/xml_23_n1config_story2076.xml")

        # Find node2 config path
        n2_config_path = self.find(
            self.ms1, node2_path, "collection-of-node-config")[0]

        # Find node2 firewall node level config path
        n2_node_config = self.find(
            self.ms1, node2_path,
            "firewall-node-config")[0]

        # 2. Export node2 firewall node config
        self.execute_cli_export_cmd(
            self.ms1, n2_node_config, "/tmp/xml_23_n2config_story2076.xml")

        try:
            # 3. Remove firewall node configs
            self.execute_cli_remove_cmd(self.ms1, n1_node_config)
            self.execute_cli_remove_cmd(self.ms1, n2_node_config)

            props = 'name="099 icmpv6" proto="ipv6-icmp" provider="ip6tables"'
            self._create_fw_rule_item(
                cluster_config_rule_path, "fw_icmpv6", props)

            # 4. Create plan
            self.execute_cli_createplan_cmd(self.ms1)

            # 5. Run plan
            self.execute_cli_runplan_cmd(self.ms1)

            # 6. Wait for plan to complete
            self.assertTrue(self.wait_for_plan_state(
                self.ms1, test_constants.PLAN_COMPLETE))

            # 7. Check firewall node config rules have been removed
            cmd_to_run = \
               "/sbin/{0} -S | /bin/grep {1} | /bin/grep '{2}' | wc -l".format(
               self.IP_TABLES, self.INPUT, "011 nfsudp")
            for node in self.test_nodes:
                self.assertTrue(self.wait_for_puppet_action(
                   self.ms1, node, cmd_to_run, 0, "0", True))

            cmd_to_run = \
               "/sbin/{0} -S | /bin/grep {1} | /bin/grep '{2}' | wc -l".format(
               self.IP_TABLES, self.INPUT, "001 nfstcp")
            for node in self.test_nodes:
                self.assertTrue(self.wait_for_puppet_action(
                   self.ms1, node, cmd_to_run, 0, "0", True))

            cmd_to_run = \
               "/sbin/{0} -S | /bin/grep {1} | /bin/grep '{2}' | wc -l".format(
               self.IP_TABLES, self.INPUT, "099 icmpipv6")
            for node in self.test_nodes:
                self.assertTrue(self.wait_for_puppet_action(
                   self.ms1, node, cmd_to_run, 0, "0", True))

            # 8. Check that the firewall cluster level rule is still present
            cmd_to_run = \
               "/sbin/{0} -S | /bin/grep {1} | /bin/grep '{2}' | wc -l".format(
               self.IP_TABLES, self.INPUT, "100 icmp")
            for node in self.test_nodes:
                self.assertTrue(self.wait_for_puppet_action(
                   self.ms1, node, cmd_to_run, 0, "1", True))

            # 9. Check that the created firewall cluster rule has been added
            cmd_to_run = \
               "/sbin/{0} -S | /bin/grep {1} | /bin/grep '{2}' | wc -l".format(
               self.IP6_TABLES, self.INPUT, "099 icmpv6")
            for node in self.test_nodes:
                self.assertTrue(self.wait_for_puppet_action(
                   self.ms1, node, cmd_to_run, 0, "1", True))

        finally:
            # 10.Load exported firewall node configs
            self.execute_cli_load_cmd(
                    self.ms1, n1_config_path,
                    "/tmp/xml_23_n1config_story2076.xml",
                    "--merge")

            self.execute_cli_load_cmd(
                    self.ms1, n2_config_path,
                    "/tmp/xml_23_n2config_story2076.xml",
                    "--merge")

            # Load firewall cluster config to remove rule
            self.execute_cli_load_cmd(
                    self.ms1, cluster_config_path,
                    "/tmp/xml_23_c1config_story2076.xml",
                    "--merge")

            # 11.Create plan
            self.execute_cli_createplan_cmd(self.ms1)

            # 12.Run plan
            self.execute_cli_runplan_cmd(self.ms1)

            # 13.Wait for plan to complete
            self.assertTrue(self.wait_for_plan_state(
                self.ms1, test_constants.PLAN_COMPLETE))

    #@attr('pre-reg', 'revert', 'story2076', 'story2076_tc24')
    def obsolete_24_p_remove_firewall_ms_config(self):
        """
        Obsoleted as functionality moved to test_01_p_load_rules_from_XML
            in testset_firewall_load_rules_xml.py

        @#tms_id: litpcds_2076_tc24
        @#tms_requirements_id: LITPCDS-2076
        @#tms_title: Remove firewall MS config
        @#tms_description: Test that if the firewall node config on the ms
            is deleted, the iptables and ip6tables are empty
        @#tms_test_steps:
            @step: Backup current firewall config by exporting it to xml
            @result: Item exported successfully
            @step: Save current MS iptables/ip6tables configuration
            @result: Current MS iptables/ip6tables configuration saved
            @step: Run a plan to remove firewall configuration item from MS
            @result: Plan is run successfully
            @result: iptables/ip6tables are empty
            @step: Restore firewall configuration and create and run plan
            @result: Plan is run successfully
            @result: Firewall configuration is back to default
        @#tms_test_precondition:NA
        @#tms_execution_type: Automated
        """
        ms_fw_config_file = "/tmp/xml_24_msconfig_story2076.xml"
        all_providers = [self.IP_TABLES, self.IP6_TABLES]

        self.log('info',
        '1. Locate firewall config items on MS')
        ms_fw_coll_config_url = self.find(self.ms1, "/ms",
                                   "collection-of-node-config")[0]

        ms_fw_config_url = self.find(self.ms1, "/ms",
                                     "firewall-node-config")[0]

        self.log('info',
        '2. Backup current firewall config by exporting it to xml')
        self.execute_cli_export_cmd(self.ms1, ms_fw_config_url,
                                    ms_fw_config_file)

        self.log('info',
        '3. Save current MS iptables/ip6tables configuration')
        iptables_default = self._get_iptables_configuration(
                                                    nodes=[self.ms1],
                                                    providers=all_providers,
                                                    tables=['filter'])
        try:
            self.log('info',
            '4. Remove firewall configuration item from MS')
            self.execute_cli_remove_cmd(self.ms1, ms_fw_config_url)
            self.run_and_check_plan(self.ms1, test_constants.PLAN_COMPLETE,
                                    plan_timeout_mins=5)

            self.log('info',
            '5. Check that MS iptables/ip6tables are empty')
            for provider in all_providers:
                for chain in ['INPUT', 'OUTPUT', 'FORWARD']:
                    cmd = (r'/sbin/{0} -S | /bin/grep "\-A {1}"'.
                          format(provider, chain))
                    _, _, rc = self.run_command(self.ms1, cmd, su_root=True)
                    self.assertEqual(1, rc,
                    'Empty configuration on "{0}" was never reached'.
                    format(provider))
        finally:
            self.log('info',
            '6. FINALLY: Restore firewall configuration')
            self.execute_cli_load_cmd(self.ms1,
                                      ms_fw_coll_config_url,
                                      ms_fw_config_file,
                                      "--merge")
            self.run_and_check_plan(self.ms1, test_constants.PLAN_COMPLETE,
                                    plan_timeout_mins=5)

            iptables_current = self._get_iptables_configuration(
                                                    nodes=[self.ms1],
                                                    providers=all_providers,
                                                    tables=['filter'])

            self.log('info',
            '7. FINALLY: Check that firewall configuration is back to default')
            for provider in all_providers:
                self.assertEqual(
                        iptables_default[self.ms1][provider]['filter'],
                        iptables_current[self.ms1][provider]['filter'],
                        'Firewall configuration did not reset to default')

    #@attr('pre-reg', 'revert', 'story2076', 'story2076_tc25')
    def obsolete_25_p_remove_fw_cluster_config_then_node_config(self):
        """
        Obsoleted as functionality moved to test_01_p_load_rules_from_XML
            in testset_firewall_load_rules_xml.py

        @#tms_id: litpcds_2076_tc25
        @#tms_requirements_id: LITPCDS-2076
        @#tms_title: Remove fw cluster config then node config
        @#tms_description: Test that if the firewall cluster config is removed,
            and there is a node level firewall config present,
            the iptables and ip6tables only contain the node level firewall
            config rules. Then when the node level firewall config is removed,
            the iptables and ip6tables are empty
        @#tms_test_steps:
            @step: Export cluster & node firewall config to XML
            @result: Item exported successfully
            @step: Create plan to remove firewall items at cluster level
            @result: Plan is run successfully
            @result: iptables and ip6tables only contain the node level rules
            @result: Iptables are as expected
            @step: Create plan to remove firewall items at node level
            @result: Plan is run successfully
            @result: iptables and ip6tables are empty
            @step: Load the exported firewall xml snippets
            @result: XML file is loaded successfully
            @step: Create plan & Run plan
            @result: Plan is run successfully
            @result: iptables and ip6tables are restored
        @#tms_test_precondition:NA
        @#tms_execution_type: Automated
        """
        # System must have at least 2 nodes to continue
        nodes_path = self.find(self.ms1, "/deployments", "node", True)
        self.assertTrue(
            len(nodes_path) > 1,
            "The LITP Tree has less than 2 nodes defined")
        node1_path = nodes_path[0]
        node2_path = nodes_path[1]

        # 1. Find cluster level config path
        cluster_config_path = self.find(
            self.ms1, "/deployments",
            "collection-of-cluster-config")[0]

        # 2. Find cluster level firewall config path
        cluster_config_rule_path = self.find(
            self.ms1, "/deployments",
            "firewall-cluster-config")[0]

        # 3. Export existing cluster firewall config
        self.execute_cli_export_cmd(
            self.ms1, cluster_config_rule_path,
            "/tmp/xml_25_c1config_story2076.xml")

        # 4. Find node1 config path
        n1_config_path = self.find(
            self.ms1, node1_path, "collection-of-node-config")[0]

        # 5. Find node1 firewall config path
        n1_node_config = self.find(
            self.ms1, node1_path,
            "firewall-node-config")[0]

        # 6. Export existing node1 firewall config
        self.execute_cli_export_cmd(
            self.ms1, n1_node_config, "/tmp/xml_25_n1config_story2076.xml")

        # 7. Find node2 config path
        n2_config_path = self.find(
            self.ms1, node2_path, "collection-of-node-config")[0]

        # 8. Find node2 firewall config path
        n2_node_config = self.find(
            self.ms1, node2_path,
            "firewall-node-config")[0]

        # 9. Export existing node2 firewall config
        self.execute_cli_export_cmd(
            self.ms1, n2_node_config, "/tmp/xml_25_n2config_story2076.xml")

        try:
            # 10.Remove existing firewall items at cluster level
            self.execute_cli_remove_cmd(self.ms1, cluster_config_rule_path)

            # 11.Create plan
            self.execute_cli_createplan_cmd(self.ms1)

            # 12.Run plan
            self.execute_cli_runplan_cmd(self.ms1)

            # 13.Wait for plan to complete
            self.assertTrue(self.wait_for_plan_state(
                self.ms1, test_constants.PLAN_COMPLETE))

            # 14.Check iptables and ip6tables only contain
            #    the node level rules
            node_rules = \
                ["'011 nfsudp'", "'001 nfstcp'"]

            for node in self.test_nodes:
                std_out, std_err, rc = self.run_command(
                    node,
                    "/sbin/iptables -L -n",
                    su_root=True)
                self.assertEquals([], std_err)
                self.assertEquals(0, rc)
                for rule in node_rules:
                    self._check_iptables(
                        node, rule, ip_tables=self.IP_TABLES)
                    self._check_iptables(
                        node, rule, ip_tables=self.IP6_TABLES)

                cmd_to_run = \
                 "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l".format(
                 self.IP6_TABLES, self.INPUT, "'101 icmpipv6'")
                self.assertTrue(self.wait_for_puppet_action
                       (self.ms1, node, cmd_to_run, 0, "1", True))

            # Check cluster level firewall rule has been removed
            for node in self.test_nodes:
                cmd_to_run = \
                 "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l".format(
                 self.IP_TABLES, self.INPUT, "'100 icmp'")
                self.assertTrue(self.wait_for_puppet_action
                       (self.ms1, node, cmd_to_run, 0, "0", True))

            # 15.Remove existing firewall items at node level
            self.execute_cli_remove_cmd(self.ms1, n1_node_config)
            self.execute_cli_remove_cmd(self.ms1, n2_node_config)

            # 16.Create plan
            self.execute_cli_createplan_cmd(self.ms1)

            # 17.Run plan
            self.execute_cli_runplan_cmd(self.ms1)

            # 18.Wait for plan to complete
            self.assertTrue(self.wait_for_plan_state(
                self.ms1, test_constants.PLAN_COMPLETE))

            # 19.Check iptables and ip6tables are empty
            for node in self.test_nodes:
                std_out, std_err, rc = self.run_command(
                    node,
                    "/sbin/iptables -L -n",
                    su_root=True)
                self.assertEquals([], std_err)
                self.assertEquals(0, rc)
                self.assertEqual(len(std_out), 6)

                std_out, std_err, rc = self.run_command(
                    node,
                    "/sbin/ip6tables -L -n",
                    su_root=True)
                self.assertEquals([], std_err)
                self.assertEquals(0, rc)
                self.assertEqual(len(std_out), 6)

                cmd_to_run = \
                 "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l".format(
                 self.IP_TABLES, self.INPUT, "'999 drop all'")
                self.assertTrue(self.wait_for_puppet_action
                       (self.ms1, node, cmd_to_run, 0, "0", True))

                cmd_to_run = \
                 "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l".format(
                 self.IP_TABLES, self.OUTPUT, "'1999 drop all'")
                self.assertTrue(self.wait_for_puppet_action
                       (self.ms1, node, cmd_to_run, 0, "0", True))

                cmd_to_run = \
                 "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l".format(
                 self.IP6_TABLES, self.INPUT, "'999 drop all v6'")
                self.assertTrue(self.wait_for_puppet_action
                       (self.ms1, node, cmd_to_run, 0, "0", True))

                cmd_to_run = \
                 "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l".format(
                 self.IP6_TABLES, self.OUTPUT, "'1999 drop all v6'")
                self.assertTrue(self.wait_for_puppet_action
                       (self.ms1, node, cmd_to_run, 0, "0", True))

        finally:
            # 20.Load the remaining exported firewall xml snippets
            self.execute_cli_load_cmd(
                    self.ms1, cluster_config_path,
                    "/tmp/xml_25_c1config_story2076.xml",
                    "--replace")

            self.execute_cli_load_cmd(
                    self.ms1, n1_config_path,
                    "/tmp/xml_25_n1config_story2076.xml",
                    "--replace")

            self.execute_cli_load_cmd(
                    self.ms1, n2_config_path,
                    "/tmp/xml_25_n2config_story2076.xml",
                    "--replace")

            # 21.Create plan
            self.execute_cli_createplan_cmd(self.ms1)

            # 22.Run plan
            self.execute_cli_runplan_cmd(self.ms1)

            # 23.Wait for plan to complete
            self.assertTrue(self.wait_for_plan_state(
                self.ms1, test_constants.PLAN_COMPLETE))

    #@attr('pre-reg', 'revert', 'story2076', 'story2076_tc26')
    def obsolete_26_p_remove_fw_node_config_then_cluster_config(self):
        """
        Obsoleted as functionality moved to test_01_p_load_rules_from_XML
            in testset_firewall_load_rules_xml.py

        @#tms_id: litpcds_2076_tc26
        @#tms_requirements_id: LITPCDS-2076
        @#tms_title: Remove fw node config then cluster config
        @#tms_description: Test that if the firewall cluster config is removed,
            and there is a node level firewall config present,
            the iptables and ip6tables only contain
            the node level firewall config rules.
            Then when the node level firewall config is removed,
            the iptables and ip6tables are empty
        @#tms_test_steps:
            @step: Export cluster & node firewall config to XML
            @result: Item exported successfully
            @step: Create plan to remove firewall items at node level
            @result: Plan is run successfully
            @result: iptables & ip6tables only contain the cluster level rules
            @result: Iptables are as expected
            @step: Create plan to remove firewall items at cluster level
            @result: Plan is run successfully
            @result: iptables and ip6tables are empty
            @step: Load the exported firewall xml snippets
            @result: XML file is loaded successfully
            @step: Create plan & Run plan
            @result: Plan is run successfully
            @result: iptables and ip6tables are restored
        @#tms_test_precondition: NA
        @#tms_execution_type: Automated
        """
        # System must have at least 2 nodes to continue
        nodes_path = self.find(self.ms1, "/deployments", "node", True)
        self.assertTrue(
            len(nodes_path) > 1,
            "The LITP Tree has less than 2 nodes defined")
        node1_path = nodes_path[0]
        node2_path = nodes_path[1]

        # 1. Find cluster level config path
        cluster_config_path = self.find(
            self.ms1, "/deployments",
            "collection-of-cluster-config")[0]

        # 2. Find cluster level firewall config path
        cluster_config_rule_path = self.find(
            self.ms1, "/deployments",
            "firewall-cluster-config")[0]

        # 3. Export existing cluster firewall config
        self.execute_cli_export_cmd(
            self.ms1, cluster_config_rule_path,
            "/tmp/xml_26_c1config_story2076.xml")

        # 4. Find node1 config path
        n1_config_path = self.find(
            self.ms1, node1_path, "collection-of-node-config")[0]

        # 5. Find node1 firewall config path
        n1_node_config = self.find(
            self.ms1, node1_path,
            "firewall-node-config")[0]

        # 6. Export existing node1 firewall config
        self.execute_cli_export_cmd(
            self.ms1, n1_node_config, "/tmp/xml_26_n1config_story2076.xml")

        # 7. Find node2 config path
        n2_config_path = self.find(
            self.ms1, node2_path, "collection-of-node-config")[0]

        # 8. Find node2 firewall config path
        n2_node_config = self.find(
            self.ms1, node2_path,
            "firewall-node-config")[0]

        # 9. Export existing node2 firewall config
        self.execute_cli_export_cmd(
            self.ms1, n2_node_config, "/tmp/xml_26_n2config_story2076.xml")

        try:
            # 10.Remove existing firewall items at node level
            self.execute_cli_remove_cmd(self.ms1, n1_node_config)
            self.execute_cli_remove_cmd(self.ms1, n2_node_config)

            # 11.Create plan
            self.execute_cli_createplan_cmd(self.ms1)

            # 12.Run plan
            self.execute_cli_runplan_cmd(self.ms1)

            # 13.Wait for plan to complete
            self.assertTrue(self.wait_for_plan_state(
                self.ms1, test_constants.PLAN_COMPLETE))

            # 14. Check firewall node config rules have been removed
            cmd_to_run = \
               "/sbin/{0} -S | /bin/grep {1} | /bin/grep '{2}' | wc -l".format(
               self.IP_TABLES, self.INPUT, "011 nfsudp")
            for node in self.test_nodes:
                self.assertTrue(self.wait_for_puppet_action(
                   self.ms1, node, cmd_to_run, 0, "0", True))

            cmd_to_run = \
               "/sbin/{0} -S | /bin/grep {1} | /bin/grep '{2}' | wc -l".format(
               self.IP_TABLES, self.INPUT, "001 nfstcp")
            for node in self.test_nodes:
                self.assertTrue(self.wait_for_puppet_action(
                   self.ms1, node, cmd_to_run, 0, "0", True))

            cmd_to_run = \
               "/sbin/{0} -S | /bin/grep {1} | /bin/grep '{2}' | wc -l".format(
               self.IP_TABLES, self.INPUT, "099 icmpipv6")
            for node in self.test_nodes:
                self.assertTrue(self.wait_for_puppet_action(
                   self.ms1, node, cmd_to_run, 0, "0", True))

            # 15. Check that the firewall cluster level rule is still present
            cmd_to_run = \
               "/sbin/{0} -S | /bin/grep {1} | /bin/grep '{2}' | wc -l".format(
               self.IP_TABLES, self.INPUT, "100 icmp")
            for node in self.test_nodes:
                self.assertTrue(self.wait_for_puppet_action(
                   self.ms1, node, cmd_to_run, 0, "1", True))

            # 16.Remove existing firewall items at cluster level
            self.execute_cli_remove_cmd(self.ms1, cluster_config_rule_path)

            # 17.Create plan
            self.execute_cli_createplan_cmd(self.ms1)

            # 18.Run plan
            self.execute_cli_runplan_cmd(self.ms1)

            # 19.Wait for plan to complete
            self.assertTrue(self.wait_for_plan_state(
                self.ms1, test_constants.PLAN_COMPLETE))

            # 20.Check iptables and ip6tables are empty
            for node in self.test_nodes:
                std_out, std_err, rc = self.run_command(
                    node,
                    "/sbin/iptables -L -n",
                    su_root=True)
                self.assertEquals([], std_err)
                self.assertEquals(0, rc)
                self.assertEqual(len(std_out), 6)

                std_out, std_err, rc = self.run_command(
                    node,
                    "/sbin/ip6tables -L -n",
                    su_root=True)
                self.assertEquals([], std_err)
                self.assertEquals(0, rc)
                self.assertEqual(len(std_out), 6)

                cmd_to_run = \
                 "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l".format(
                 self.IP_TABLES, self.INPUT, "'999 drop all'")
                self.assertTrue(self.wait_for_puppet_action
                       (self.ms1, node, cmd_to_run, 0, "0", True))

                cmd_to_run = \
                 "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l".format(
                 self.IP_TABLES, self.OUTPUT, "'1999 drop all'")
                self.assertTrue(self.wait_for_puppet_action
                       (self.ms1, node, cmd_to_run, 0, "0", True))

                cmd_to_run = \
                 "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l".format(
                 self.IP6_TABLES, self.INPUT, "'999 drop all v6'")
                self.assertTrue(self.wait_for_puppet_action
                       (self.ms1, node, cmd_to_run, 0, "0", True))

                cmd_to_run = \
                 "/sbin/{0} -S | /bin/grep {1} | /bin/grep {2} | wc -l".format(
                 self.IP6_TABLES, self.OUTPUT, "'1999 drop all v6'")
                self.assertTrue(self.wait_for_puppet_action
                       (self.ms1, node, cmd_to_run, 0, "0", True))

        finally:
            # 21.Load the remaining exported firewall xml snippets
            self.execute_cli_load_cmd(
                    self.ms1, cluster_config_path,
                    "/tmp/xml_26_c1config_story2076.xml",
                    "--replace")

            self.execute_cli_load_cmd(
                    self.ms1, n1_config_path,
                    "/tmp/xml_26_n1config_story2076.xml",
                    "--replace")

            self.execute_cli_load_cmd(
                    self.ms1, n2_config_path,
                    "/tmp/xml_26_n2config_story2076.xml",
                    "--replace")

            # 22.Create plan
            self.execute_cli_createplan_cmd(self.ms1)

            # 23.Run plan
            self.execute_cli_runplan_cmd(self.ms1)

            # 24.Wait for plan to complete
            self.assertTrue(self.wait_for_plan_state(
                self.ms1, test_constants.PLAN_COMPLETE))

    #@attr('pre-reg', 'revert', 'story2892', 'story2892_tc28')
    def obsolete_28_n_check_ports_are_closed(self):
        """
        Obsoleted as functionality moved to test_01_p_default_ports in
            testset_firewall_rule_positive.py

        @#tms_id: litpcds_2892_tc28
        @#tms_requirements_id: LITPCDS-2892
        @#tms_title: Check ports are closed
        @#tms_description: This test verifies that the following port
            is closed on the ms by iptables: 5672
            and that ports 5672, 61613 are closed on the mns
        @#tms_test_steps:
            @step: Check iptables on ms/nodes contain correct rules
            @result: Correct default ports are closed
        @#tms_test_precondition:NA
        @#tms_execution_type: Automated
        """
        test_closed_ports_ms = ["5672"]
        test_closed_ports_mns = ["5672", "61613"]

        # 1. Check iptables on ms/nodes contain correct rules
        for iptables in [self.IP_TABLES, self.IP6_TABLES]:
            for node in self.test_nodes:
                for port in test_closed_ports_mns:
                    self._check_iptables(
                        node,
                        'dports | /bin/grep -w {0}'.format(port),
                        ip_tables=iptables, expect_positive=False)
            for port in test_closed_ports_ms:
                self._check_iptables(
                    self.ms1,
                    'dports | /bin/grep -w {0}'.format(port),
                    ip_tables=iptables, expect_positive=False)

    #@attr('pre-reg', 'revert', 'story106903', 'story106903_tc30')
    def obsolete_30_p_create_update_remove_duplicate_rule_split_chain(self):
        """
        Obsoleted as functionality moved to test_01_n_duplicate_validation
            in testset_firewall_load_rules_xml.py

        @#tms_id: torf_106903_tc30
        @#tms_requirements_id: TORF-106903
        @#tms_title: Check ports are closed
        @#tms_description:  Verify that a user can create rules with same chain
            number and different name provided they apply to different chains.
            Actions: Verify that attempt to update chain property on one of
            such rules so that it conflicts with other existing rule is
            prevented. Verify that if the duplicate rule is removed the rule
            that was updated can successfully be deployed.
        @#tms_test_steps:
            @step: Create plan to add two fw rules with same chain sequence
                number and that apply to different chains on MS
            @result: Plan completes successfully
            @result: correct rules have been added to iptables
            @step: Update property chain on one of the rules
                to cause a duplicate rule error & create plan
            @result: Expected error seen.
            @step: Update property chain on the other the rules so that the
                duplicate is removed & create and run plan
            @result: Plan completes successfully
            @result: Iptables updated successfully
            @step: Delete property chain from one of the rules & create plan
            @result: create plan failed with expected error message
            @step: Create plan to remove rule created during this test
            @result: Plan completes successfully
            @result: The correct rules are in the iptables
        @#tms_test_precondition:NA
        @#tms_execution_type: Automated
        """
        story_id = '106903'
        tc_id = '{0}_tc30'.format(story_id)
        all_nodes = [self.ms1]
        all_providers = [self.IP_TABLES, self.IP6_TABLES]
        all_tables = ['filter', 'raw', 'mangle', 'nat']

        self.log('info',
        '1. Get initial iptables configuration')
        self._get_iptables_configuration(all_nodes, all_providers, all_tables)

        self.log('info',
        '2. Locate firewall-node-config item on MS - create it if missing')
        ms_fw_node_conf_urls = self.find(self.ms1, '/ms',
                                         'firewall-node-config',
                                          assert_not_empty=False)
        if not ms_fw_node_conf_urls:
            ms_coll_node_config_url = self.find(self.ms1, '/ms',
                                                'collection-of-node-config')[0]
            ms_fw_node_conf_url = ('{0}/fw_config_init'.
                                   format(ms_coll_node_config_url))
            self.execute_cli_create_cmd(self.ms1,
                                        ms_fw_node_conf_url,
                                        'firewall-node-config')
        else:
            ms_fw_node_conf_url = ms_fw_node_conf_urls[0]

        self.log('info',
        '3. Create two fw rules with same chain sequence number and that '
              'apply to different chains')
        rule_set = {
        'rule 01': {
            'props': 'name="080 in chain" chain=INPUT dport=9999',
            'url': '{0}/rules/fw_{1}_01'.format(ms_fw_node_conf_url, tc_id),
            'expected_ipv4_rules': [
                ['-A INPUT', '-p tcp', '--dport 9999',
                 '-m comment --comment "080 in chain ipv4"',
                 '-m state --state NEW', '-j ACCEPT'],
            ],
            'expected_ipv6_rules': [
                ['-A INPUT', '-p tcp', '--dport 9999',
                 '-m comment --comment "080 in chain ipv6"',
                 '-m state --state NEW', '-j ACCEPT'],
            ]
        },
        'rule 02': {
            'props': 'name="080 out chain" chain=OUTPUT sport=9999',
            'url': '{0}/rules/fw_{1}_02'.format(ms_fw_node_conf_url, tc_id),
            'expected_ipv4_rules': [
                ['-A OUTPUT', '-p tcp', '--sport 9999',
                 '-m comment --comment "1080 out chain ipv4"',
                 '-m state --state NEW', '-j ACCEPT']
            ],
            'expected_ipv6_rules': [
                ['-A OUTPUT', '-p tcp', '--sport 9999',
                 '-m comment --comment "1080 out chain ipv6"',
                 '-m state --state NEW', '-j ACCEPT']
            ]
        },
        }

        for rule in sorted(rule_set.keys()):
            self.execute_cli_create_cmd(self.ms1,
                                        rule_set[rule]['url'],
                                        'firewall-rule',
                                        rule_set[rule]['props'])

        self.log('info',
        '4. Deploy new firwall items')
        self.run_and_check_plan(self.ms1,
            expected_plan_state=test_constants.PLAN_COMPLETE,
            plan_timeout_mins=10)

        self.log('info',
        '5. Get iptables configuration')
        iptables_current = self._get_iptables_configuration(
                                        all_nodes, all_providers, all_tables)

        self.log('info',
        '6. Check that the correct rules have been added to firewalls')
        missing_rules = self._check_all_expected_rules_are_applied(
                                        all_nodes, iptables_current, rule_set)

        self.assertEqual([], missing_rules,
                         '\nFollowing firewall rules were not found\n{0}'.
                         format('\n'.join(missing_rules)))

        self.log('info',
        '7. Update property chain on one of the rules just created '
              'to cause a duplicate rule error')
        self.execute_cli_update_cmd(self.ms1,
            rule_set['rule 01']['url'], props='chain=OUTPUT')

        self.log('info',
        '8. Attempt to create plan and check for errors')
        _, stderr, _ = self.execute_cli_createplan_cmd(self.ms1,
                                                       expect_positive=False)

        expected_errors = [
            {
                'url': rule_set['rule 01']['url'],
                'msg': "ValidationError    Create plan failed: Position "
                       "'80' in the firewall chain 'OUTPUT' is not "
                       "unique on node 'ms1'"
            },
            {
                'url': rule_set['rule 02']['url'],
                'msg': "ValidationError    Create plan failed: Position "
                       "'80' in the firewall chain 'OUTPUT' is not "
                       "unique on node 'ms1'"
            },
        ]

        missing, extra = self._check_cli_errors(expected_errors, stderr)
        self.assertEqual([], missing,
            '\nMISSING ERRORS:\n{0}'.format('\n'.join(missing)))
        self.assertEqual([], extra,
            '\nEXTRA ERRORS:\n{0}'.format('\n'.join(extra)))

        self.log('info',
        '9. Update property chain on the other the rules so that the '
              'duplicate is removed')
        self.execute_cli_update_cmd(self.ms1,
            rule_set['rule 02']['url'], props='chain=INPUT')

        self.log('info',
        'Verify that plan can be created and run successfully')
        self.run_and_check_plan(self.ms1,
                        expected_plan_state=test_constants.PLAN_COMPLETE,
                        plan_timeout_mins=10)

        self.log('info',
        '10. Delete property chain from one of the two rules')
        self.execute_cli_update_cmd(self.ms1, rule_set['rule 01']['url'],
                                    props='chain', action_del=True)

        self.log('info',
        '11. Attempt to create plan and check for errors')
        _, stderr, _ = self.execute_cli_createplan_cmd(self.ms1,
                                                       expect_positive=False)

        expected_errors = [
            {
                'url': rule_set['rule 01']['url'],
                'msg': "ValidationError    Create plan failed: Position "
                       "'80' in the firewall chain 'INPUT' is not "
                       "unique on node 'ms1'"
            },
            {
                'url': rule_set['rule 02']['url'],
                'msg': "ValidationError    Create plan failed: Position "
                       "'80' in the firewall chain 'INPUT' is not "
                       "unique on node 'ms1'"
            },
        ]

        missing, extra = self._check_cli_errors(expected_errors, stderr)
        self.assertEqual([], missing,
            '\nMISSING ERRORS:\n{0}'.format('\n'.join(missing)))
        self.assertEqual([], extra,
            '\nEXTRA ERRORS:\n{0}'.format('\n'.join(extra)))

        self.log('info',
        '12. Remove the other rule created during this test')
        self.execute_cli_remove_cmd(self.ms1, rule_set['rule 02']['url'])

        self.log('info',
        '13. Verify that plan can be created and run successfully')
        self.run_and_check_plan(self.ms1,
                        expected_plan_state=test_constants.PLAN_COMPLETE,
                        plan_timeout_mins=10)

        self.log('info',
        '14. Get iptables configuration')
        iptables_current = self._get_iptables_configuration(
                                        all_nodes, all_providers, all_tables)

        self.log('info',
        '15. Check that the correct rules are in firewalls')
        rule_set = {
        'rule 01': {
            'expected_ipv4_rules': [
                ['-A INPUT', '-p tcp', '--dport 9999',
                 '-m comment --comment "080 in chain ipv4"',
                 '-m state --state NEW', '-j ACCEPT'],
                ['-A OUTPUT', '-p tcp', '--dport 9999',
                 '-m comment --comment "1080 in chain ipv4"',
                 '-m state --state NEW', '-j ACCEPT'],
            ],
            'expected_ipv6_rules': [
                ['-A INPUT', '-p tcp', '--dport 9999',
                 '-m comment --comment "080 in chain ipv6"',
                 '-m state --state NEW', '-j ACCEPT'],
                ['-A OUTPUT', '-p tcp', '--dport 9999',
                 '-m comment --comment "1080 in chain ipv6"',
                 '-m state --state NEW', '-j ACCEPT'],
            ]
        },
        }

        missing_rules = self._check_all_expected_rules_are_applied(
                                        all_nodes, iptables_current, rule_set)

        self.assertEqual([], missing_rules,
                         '\nFollowing firewall rules were not found\n{0}'.
                         format('\n'.join(missing_rules)))

    #@attr('pre-reg', 'revert', 'story106903', 'story106903_tc31')
    def obsolete_31_p_remove_and_create_same_rule(self):
        """
        Obsoleted as functionality moved to test_01_n_duplicate_validation
            in testset_firewall_load_rules_xml.py

        @#tms_id: torf_106903_tc31
        @#tms_requirements_id: TORF-106903
        @#tms_title: Remove and create same rule
        @#tms_description:  Verify that a user can remove and create
            same rule in one single plan
        @#tms_test_steps:
            @step: Create a plan to add two unique fw rules
            @result: Plan completes successfully
            @result: Correct rules have been added to iptables
            @step: Run litp remove command on rules that have been added
            @result: Rules are marked as ForRemoval
            @step: Re-create & update the rules marked ForRemoval & run plan
            @result: Plan completes successfully
            @result: The correct rules are in the iptables
        @#tms_test_precondition:NA
        @#tms_execution_type: Automated
        """
        story_id = '106903'
        tc_id = '{0}_tc31'.format(story_id)
        all_nodes = [self.mn1, self.mn2]
        all_providers = [self.IP_TABLES, self.IP6_TABLES]
        all_tables = ['filter', 'raw', 'mangle', 'nat']

        self.log('info',
        '1. Get initial iptables configuration')
        self._get_iptables_configuration(all_nodes, all_providers, all_tables)

        self.log('info',
        '2. Locate firewall-cluster-config item - create it if missing')
        cl_coll_configs_url = self.find(self.ms1, '/deployments',
                                        'collection-of-cluster-config')[0]

        cl_fw_conf_urls = self.find(self.ms1, cl_coll_configs_url,
                                    'firewall-cluster-config',
                                     assert_not_empty=False)

        if not cl_fw_conf_urls:
            cl_fw_conf_url = '{0}/fw_config_init'.format(cl_coll_configs_url)
            self.execute_cli_create_cmd(self.ms1,
                                        cl_fw_conf_url,
                                        'firewall-cluster-config')
        else:
            cl_fw_conf_url = cl_fw_conf_urls[0]

        self.log('info',
        '3. Locate firewall-node-config item - create it if missing')
        node_url = self.find(self.ms1, '/deployments', 'node')[0]
        node_coll_config_url = self.find(
            self.ms1,
            node_url,
            'collection-of-node-config',
            assert_not_empty=False)[0]

        node_fw_node_config_urls = self.find(
            self.ms1,
            node_coll_config_url,
            'firewall-node-config',
            assert_not_empty=False)

        if not node_fw_node_config_urls:
            node_fw_node_config_url = ('{0}/fw_config_init'.
                                      format(node_coll_config_url))
            self.execute_cli_create_cmd(self.ms1,
                                        node_fw_node_config_url,
                                        'firewall-node-config')
        else:
            node_fw_node_config_url = node_fw_node_config_urls[0]

        self.log('info',
        '4. Create two unique fw rules which will be then removed and '
            're-created at same time')
        rule_set = {
        'rule 01': {
            'props': 'name="081 create remove" dport="12321"',
            'url': '{0}/rules/fw_{1}_03'.
                   format(cl_fw_conf_url, tc_id),
            'expected_ipv4_rules': [
                ['-A INPUT', '-p tcp', '--dport 12321',
                 '-m comment --comment "081 create remove ipv4"',
                 '-m state --state NEW', '-j ACCEPT'],
                ['-A OUTPUT', '-p tcp', '--dport 12321',
                 '-m comment --comment "1081 create remove ipv4"',
                 '-m state --state NEW', '-j ACCEPT'],
            ],
            'expected_ipv6_rules': [
                ['-A INPUT', '-p tcp', '--dport 12321',
                 '-m comment --comment "081 create remove ipv6"',
                 '-m state --state NEW', '-j ACCEPT'],
                ['-A OUTPUT', '-p tcp', '--dport 12321',
                 '-m comment --comment "1081 create remove ipv6"',
                 '-m state --state NEW', '-j ACCEPT'],
            ]
        },
        'rule 02': {
            'props': 'name="082 create remove" sport="22345"',
            'url': '{0}/rules/fw_{1}_03'.
                    format(node_fw_node_config_url, tc_id),
            'nodes': [self.mn1],
            'expected_ipv4_rules': [
                ['-A INPUT', '-p tcp', '--sport 22345',
                 '-m comment --comment "082 create remove ipv4"',
                 '-m state --state NEW', '-j ACCEPT'],
                ['-A OUTPUT', '-p tcp', '--sport 22345',
                 '-m comment --comment "1082 create remove ipv4"',
                 '-m state --state NEW', '-j ACCEPT'],
            ],
            'expected_ipv6_rules': [
                ['-A INPUT', '-p tcp', '--sport 22345',
                 '-m comment --comment "082 create remove ipv6"',
                 '-m state --state NEW', '-j ACCEPT'],
                ['-A OUTPUT', '-p tcp', '--sport 22345',
                 '-m comment --comment "1082 create remove ipv6"',
                 '-m state --state NEW', '-j ACCEPT'],
            ]
        },
        }

        for rule in sorted(rule_set.keys()):
            self.execute_cli_create_cmd(self.ms1,
                                        rule_set[rule]['url'],
                                        'firewall-rule',
                                        rule_set[rule]['props'])

        self.log('info',
        '5. Create and run the plan')
        self.run_and_check_plan(self.ms1,
            expected_plan_state=test_constants.PLAN_COMPLETE,
            plan_timeout_mins=10)

        self.log('info',
        '6. Get iptables configuration')
        iptables_current = self._get_iptables_configuration(
                                        all_nodes, all_providers, ['filter'])

        self.log('info',
        '7. Check that the correct rules have been added to firewalls')
        missing_rules = self._check_all_expected_rules_are_applied(
                                        all_nodes, iptables_current, rule_set)

        self.assertEqual([], missing_rules,
                         '\nFollowing firewall rules were not found\n{0}'.
                         format('\n'.join(missing_rules)))

        self.log('info',
        '8. Mark the rules just created as ForRemoval')
        self.execute_cli_remove_cmd(self.ms1, rule_set['rule 01']['url'])
        self.execute_cli_remove_cmd(self.ms1, rule_set['rule 02']['url'])

        self.log('info',
        '9. Re-create the rules marked ForRemoval')
        rule_set['rule 01']['props'] = \
                             'name="081 create remove" dport="33654"'
        rule_set['rule 01']['expected_ipv4_rules'] = [
                ['-A INPUT', '-p tcp', '--dport 33654',
                 '-m comment --comment "081 create remove ipv4"',
                 '-m state --state NEW', '-j ACCEPT'],
                ['-A OUTPUT', '-p tcp', '--dport 33654',
                 '-m comment --comment "1081 create remove ipv4"',
                 '-m state --state NEW', '-j ACCEPT']
            ]
        rule_set['rule 01']['expected_ipv6_rules'] = [
                ['-A INPUT', '-p tcp', '--dport 33654',
                 '-m comment --comment "081 create remove ipv6"',
                 '-m state --state NEW', '-j ACCEPT'],
                ['-A OUTPUT', '-p tcp', '--dport 33654',
                 '-m comment --comment "1081 create remove ipv6"',
                 '-m state --state NEW', '-j ACCEPT'],
            ]
        self.execute_cli_create_cmd(self.ms1,
                                    rule_set['rule 01']['url'],
                                    'firewall-rule',
                                    rule_set['rule 01']['props'])

        rule_set['rule 02']['props'] = \
                             'name="082 create remove" sport="33789"'

        rule_set['rule 02']['expected_ipv4_rules'] = [
                ['-A INPUT', '-p tcp', '--sport 33789',
                 '-m comment --comment "082 create remove ipv4"',
                 '-m state --state NEW', '-j ACCEPT']
            ]
        rule_set['rule 02']['expected_ipv6_rules'] = [
                ['-A INPUT', '-p tcp', '--sport 33789',
                 '-m comment --comment "082 create remove ipv6"',
                 '-m state --state NEW', '-j ACCEPT']
            ]

        self.execute_cli_create_cmd(self.ms1,
                                    rule_set['rule 02']['url'],
                                    'firewall-rule',
                                    rule_set['rule 02']['props'])

        self.log('info',
        '10. Create and run the plan')
        self.run_and_check_plan(self.ms1,
            expected_plan_state=test_constants.PLAN_COMPLETE,
            plan_timeout_mins=10)

        self.log('info',
        '11. Get iptables configuration')
        iptables_current = self._get_iptables_configuration(
                                        all_nodes, all_providers, all_tables)

        self.log('info',
        '12. Check that the correct rules have been added to firewalls')
        missing_rules = self._check_all_expected_rules_are_applied(
                                        all_nodes, iptables_current, rule_set)

        self.assertEqual([], missing_rules,
                         '\nFollowing firewall rules were not found\n{0}'.
                         format('\n'.join(missing_rules)))

    #@attr('pre-reg', 'revert', 'story106903', 'story106903_tc32')
    def obsolete_32_n_remove_rule_from_cluster_and_create_on_node(self):
        """
        Obsoleted as functionality moved to test_01_n_duplicate_validation
            in testset_firewall_load_rules_xml.py

        @#tms_id: torf_106903_tc32
        @#tms_requirements_id: TORF-106903
        @#tms_title: Remove rule from cluster  & create on node
        @#tms_description:  Verify that a user cannot remove a firewall rule at
            cluster level and create same rule at node level in one single plan
        @#tms_test_steps:
            @step: Create a plan to a rule at cluster level
            @result: Plan completes successfully
            @result: Correct rules have been added to iptables
            @step: Mark the rule just deployed ForRemoval and re-create the
                same rule at node level & create plan
            @result: create plan fails with the expected message
            @step: Update name of the rule to be created at node level so
                that it does not conflict & create & run the plan
            @result: Plan completes successfully
            @result: The correct rules are in the iptables
        @#tms_test_precondition:NA
        @#tms_execution_type: Automated
        """
        story_id = '106903'
        tc_id = '{0}_tc32'.format(story_id)
        all_nodes = [self.mn1, self.mn2]
        all_providers = [self.IP_TABLES, self.IP6_TABLES]
        all_tables = ['filter', 'raw', 'mangle', 'nat']

        self.log('info',
        '1. Get initial iptables configuration')
        self._get_iptables_configuration(all_nodes, all_providers, all_tables)

        self.log('info',
        '2. Locate firewall-cluster-config item - create it if missing')
        cl_coll_configs_url = self.find(self.ms1, '/deployments',
                                        'collection-of-cluster-config')[0]

        cl_fw_conf_urls = self.find(self.ms1, cl_coll_configs_url,
                                    'firewall-cluster-config',
                                     assert_not_empty=False)

        if not cl_fw_conf_urls:
            cl_fw_conf_url = '{0}/fw_config_init'.format(cl_coll_configs_url)
            self.execute_cli_create_cmd(self.ms1,
                                        cl_fw_conf_url,
                                        'firewall-cluster-config')
        else:
            cl_fw_conf_url = cl_fw_conf_urls[0]

        self.log('info',
        '3. Locate firewall-node-config item - create it if missing')
        node_url = self.find(self.ms1, '/deployments', 'node')[0]
        node_coll_config_url = self.find(
            self.ms1,
            node_url,
            'collection-of-node-config',
            assert_not_empty=False)[0]

        node_fw_node_config_urls = self.find(
            self.ms1,
            node_coll_config_url,
            'firewall-node-config',
            assert_not_empty=False)

        if not node_fw_node_config_urls:
            node_fw_node_config_url = ('{0}/fw_config_init'.
                                      format(node_coll_config_url))
            self.execute_cli_create_cmd(self.ms1,
                                        node_fw_node_config_url,
                                        'firewall-node-config')
        else:
            node_fw_node_config_url = node_fw_node_config_urls[0]

        self.log('info',
        '4. Create a rule at cluster level')
        rule_set = {
        'rule 01': {
            'props': 'name="081 remove create" dport="12321"',
            'url': '{0}/rules/fw_{1}_03'.
                   format(cl_fw_conf_url, tc_id),
            'expected_ipv4_rules': [
                ['-A INPUT', '-p tcp', '--dport 12321',
                 '-m comment --comment "081 remove create ipv4"',
                 '-m state --state NEW', '-j ACCEPT'],
                ['-A OUTPUT', '-p tcp', '--dport 12321',
                 '-m comment --comment "1081 remove create ipv4"',
                 '-m state --state NEW', '-j ACCEPT']
            ],
            'expected_ipv6_rules': [
                ['-A INPUT', '-p tcp', '--dport 12321',
                 '-m comment --comment "081 remove create ipv6"',
                 '-m state --state NEW', '-j ACCEPT'],
                ['-A OUTPUT', '-p tcp', '--dport 12321',
                 '-m comment --comment "1081 remove create ipv6"',
                 '-m state --state NEW', '-j ACCEPT']
            ]
        }
        }

        self.execute_cli_create_cmd(self.ms1,
                                    rule_set['rule 01']['url'],
                                    'firewall-rule',
                                    rule_set['rule 01']['props'])

        self.log('info',
        '5. Create and run the plan')
        self.run_and_check_plan(self.ms1,
            expected_plan_state=test_constants.PLAN_COMPLETE,
            plan_timeout_mins=10)

        self.log('info',
        '6. Get iptables configuration')
        iptables_current = self._get_iptables_configuration(
                                        all_nodes, all_providers, all_tables)

        self.log('info',
        '7. Check that the correct rules have been added to firewalls')
        missing_rules = self._check_all_expected_rules_are_applied(
                                        all_nodes, iptables_current, rule_set)

        self.assertEqual([], missing_rules,
                         '\nFollowing firewall rules were not found\n{0}'.
                         format('\n'.join(missing_rules)))

        self.log('info',
        '8. Mark the rule just deployed ForRemoval and re-create the same '
            'rule at node level')
        self.execute_cli_remove_cmd(self.ms1, rule_set['rule 01']['url'])

        rule_set['rule 02'] = {}
        rule_set['rule 02']['url'] = \
            '{0}/rules/fw_{1}_03'.format(node_fw_node_config_url, tc_id)
        rule_set['rule 02']['props'] = \
            'name="081 remove create" dport="12321"'
        rule_set['rule 02']['nodes'] = [self.mn1]

        self.execute_cli_create_cmd(self.ms1,
                                    rule_set['rule 02']['url'],
                                    'firewall-rule',
                                    rule_set['rule 02']['props'])

        self.log('info',
        '9. Attempt to create plan and expect fail')
        _, stderr, _ = self.execute_cli_createplan_cmd(self.ms1,
                                                       expect_positive=False)

        self.log('info', '10. Check errors')
        expected_errors = [
            {
                'url': rule_set['rule 01']['url'],
                'msg': "ValidationError    Create plan failed: Rule name "
                       "'081 remove create' is not unique for reused "
                       "chain number"
            },
            {
                'url': rule_set['rule 02']['url'],
                'msg': "ValidationError    Create plan failed: Rule name "
                       "'081 remove create' is not unique for reused "
                       "chain number"
            }
        ]

        missing, extra = self._check_cli_errors(expected_errors, stderr)
        self.assertEqual([], missing,
            '\nMISSING ERRORS:\n{0}'.format('\n'.join(missing)))
        self.assertEqual([], extra,
            '\nEXTRA ERRORS:\n{0}'.format('\n'.join(extra)))

        self.log('info',
        '11. Update name of the rule to be created at node level so that it '
            'does not conflict')

        rule_set['rule 02']['props'] = 'name="081 new name"'
        self.execute_cli_update_cmd(self.ms1,
                                    url=rule_set['rule 02']['url'],
                                    props=rule_set['rule 02']['props'])

        self.log('info',
        '12. Create and run the plan')
        self.run_and_check_plan(self.ms1,
                            expected_plan_state=test_constants.PLAN_COMPLETE,
                            plan_timeout_mins=10)

        rule_set.pop('rule 01')

        rule_set['rule 02']['expected_ipv4_rules'] = [
                ['-A INPUT', '-p tcp', '--dport 12321',
                 '-m comment --comment "081 new name ipv4"',
                 '-m state --state NEW', '-j ACCEPT'],
                ['-A OUTPUT', '-p tcp', '--dport 12321',
                 '-m comment --comment "1081 new name ipv4"',
                 '-m state --state NEW', '-j ACCEPT']
            ]

        rule_set['rule 02']['expected_ipv6_rules'] = [
                ['-A INPUT', '-p tcp', '--dport 12321',
                 '-m comment --comment "081 new name ipv6"',
                 '-m state --state NEW', '-j ACCEPT'],
                ['-A OUTPUT', '-p tcp', '--dport 12321',
                 '-m comment --comment "1081 new name ipv6"',
                 '-m state --state NEW', '-j ACCEPT']
            ]

        self.log('info',
        '13. Get iptables configuration')
        iptables_current = self._get_iptables_configuration(
                                        all_nodes, all_providers, all_tables)

        self.log('info',
        '14. Check that the correct rules have been added to firewalls')
        missing_rules = self._check_all_expected_rules_are_applied(
                                        all_nodes, iptables_current, rule_set)

        self.assertEqual([], missing_rules,
                         '\nFollowing firewall rules were not found\n{0}'.
                         format('\n'.join(missing_rules)))

    #@attr('pre-reg', 'revert', 'story200553', 'story200553_tc01')
    def obsolete_33_p_create_firewall_rules_with_string_algo(self):
        """
        Obsoleted as functionality moved to test_02_p_create_rules and
        test_03_p_update_remove_rules in testset_firewall_rule_positive.py

        @#tms_id: torf_200553_tc01
        @#tms_requirements_id: TORF-200553
        @#tms_title: Test creation/deletion of firewall rules with
         STRING and ALGO properties and with negated source property
        @#tms_description: Test to verify that user can create/delete firewall
        rules with new properties STRING and ALGO and with supported negation
        of SOURCE property. Check that user can create/delete rules with
        state=none (as for TORF-214102)
        @#tms_test_steps:
            @step: Read firewall default configuration
            @result: Iptables initial config saved
            @step: Create firewall rules to be used in this test
            @result: firewall rules created
            @step: Create rules with "string" and "algo" property values
            @result: Rules are created successfully in litp model
            @step: Create rules with negated "source" IP/subnet values
            @result: Rules are created successfully in litp model
            @step: Create rules with negated "source" IP/subnet values
            with whitespace between "!" and IP/subnet
            @result: Rules are created successfully in litp model
            @step: Create rules for dport, sport and state=none
            @result: Rules are created successfully in litp model
            @step: Create and run plan
            @result: Plan is created and runs successfully
            @step: Log "iptables" configuration after creating new rules
            @result: "iptables" are logged
            @step: Check that the following rules have been added to firewalls
            @result: rules have been added to firewalls
            @step: Check the rules order
            @result: The rules are added in proper order
            @step: Reboot all nodes
            @result: Nodes are rebooted
            @step: Check that the rules persist in iptables
            @result: The added rules are still in iptables
            @step: Remove created rules
            @result: Rules removed
            @step: Read current firewall configuration
            @result: current firewall configuration read
            @step: Verify that firewall configuration is back to default config
            @result: firewall configuration is back to default config
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
                 '1. Read firewall default configuration')
        iptables_initial_config = self._get_iptables_configuration(
            all_nodes, all_providers, all_tables)

        self.log('info',
                 '2. Define firewall rules to be use in this test')
        rule_set_file = ('{0}/test_33_rule_set_story200553'.
                         format(os.path.dirname(__file__)))
        rule_set = self._load_rule_set(rule_set_file)
        rule_set_nodefile = ('{0}/test_33_rule_set_story200553_node'.
                             format(os.path.dirname(__file__)))

        rule_set_node = self._load_rule_set(rule_set_nodefile)

        self.log('info',
                 '3. Create cluster firewall config items')
        fw_conf_url_cluster = self._create_fw_config(
                                                "fw_story200553_tc01_config")
        fw_conf_url_node = self._create_fw_config("fw_story200553_tc01_node",
                                                  False)

        self.log('info',
                 '4. Create firewall rule items at cluster and node level')
        self._create_update_rules(rule_set, fw_conf_url_cluster,
                                  initial_rules=initial_rules)
        self._create_update_rules(rule_set_node, fw_conf_url_node, node=True,
                                  initial_rules=initial_rules)
        # Sorted list of initial rules names, needed for order check later on
        initial_rules_sorted = sorted(initial_rules)

        self.log('info',
                 '5. Create and run plan')
        self._create_run_and_wait_for_plan_state(test_constants.PLAN_COMPLETE,
                                                 'Plan to deploy firewall'
                                                 ' rules failed')

        self.log('info',
                 '6. Log "iptables" configuration after creating new rules')
        iptables = self._get_iptables_configuration(all_nodes, all_providers,
                                                    all_tables)

        self.log('info',
                 '7. Check that the rules have been added to firewalls')
        missing_rules = self._check_all_expected_rules_are_applied(
            all_nodes, iptables, rule_set)
        missing_rules_node = self._check_all_expected_rules_are_applied(
            node_1, iptables, rule_set_node)

        for rules in missing_rules, missing_rules_node:
            self._assert_rules_applied(rules)

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
        self.assertEqual(compare_input_lists, 0,
                         "The input lists don't match")
        self.assertEqual(compare_output_lists, 0,
                         "The output lists don't match")

        self.log('info', '9. Reboot the nodes')
        self._vcs_reboot_and_wait_for_system(self.mn2, self.mn1)
        self._vcs_reboot_and_wait_for_system(self.mn1, self.mn2)

        self.log('info',
                 '10. Check that the following rules persist after reboot')
        missing_rules = self._check_all_expected_rules_are_applied(
            all_nodes, iptables, rule_set)
        missing_rules_node = self._check_all_expected_rules_are_applied(
            node_1, iptables, rule_set_node)
        for rules in missing_rules, missing_rules_node:
            self._assert_rules_applied(rules)

        self.log('info',
                 '11. Remove created rules')
        for case in sorted(rule_set.keys()):
            self.execute_cli_remove_cmd(self.ms1, rule_set[case]['url'])

        for case in sorted(rule_set_node.keys()):
            self.execute_cli_remove_cmd(self.ms1, rule_set_node[case]['url'])

        self._create_run_and_wait_for_plan_state(test_constants.PLAN_COMPLETE,
                                                 'Plan to remove rules created'
                                                 'during test failed')

        self.log('info',
                 '12. Read current firewall configuration')
        iptables_current_config = self._get_iptables_configuration(
                                        all_nodes, all_providers, all_tables)

        self.log('info',
                 '13. Verify that firewall configuration is back to deafult')
        for node in all_nodes:
            for provider in all_providers:
                for table in all_tables:
                    if provider == self.IP6_TABLES and table == 'nat':
                        continue
                    self.assertEqual(
                        iptables_initial_config[node][provider][table],
                        iptables_current_config[node][provider][table],
                        'Firewall configuration did not reset to default '
                        'after removing all rules created during test')

    #@attr('pre-reg', 'revert', 'story200553', 'story200553_tc02')
    def obsolete_34_p_update_firewall_rules_with_string_algo(self):
        """
        Obsoleted as functionality moved to test_03_p_update_remove_rules
            in testset_firewall_rule_positive.py

        @#tms_id: torf_200553_tc02
        @#tms_requirements_id: TORF-200553
        @#tms_title: Test updating of firewall rules with
         STRING and ALGO properties and with negated source property
        @#tms_description: Test to verify that user can update firewall
        rules with new properties STRING and ALGO and with supported negation
        of SOURCE property
        @#tms_test_steps:
            @step: Create firewall rules to be used in this test
            @result: firewall rules created
            @step: Create rules with "string" and "algo" property values
            @result: Rules are created successfully in litp model
            @step: Create rules with negated "source" IP/subnet values
            @result: Rules are created successfully in litp model
            @step: Update "string" and "algo" values for rules
            @result: Parameters are updated
            @step: Update "source" parameter to negated one
            @result: Parameters are updated
            @step: Create and run plan
            @result: Plan is created and runs successfully
            @step: Log "iptables" configuration after creating new rules
            @result: "iptables" are logged
            @step: Check that the following rules have been added to firewalls
            @result: rules have been added to firewalls
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
        rule_set_file = ('{0}/test_34_rule_set_story200553'.
                         format(os.path.dirname(__file__)))
        rule_set = self._load_rule_set(rule_set_file)
        rule_set_nodefile = ('{0}/test_34_rule_set_story200553_node'.
                             format(os.path.dirname(__file__)))
        rule_set_node = self._load_rule_set(rule_set_nodefile)
        cluster_rule_names = []
        node_rule_names = []

        self.log('info',
                 '2. Create firewall config items')
        fw_conf_url_cluster = self._create_fw_config(
                                                "fw_story200553_tc01_config")
        fw_conf_url_node = self._create_fw_config("fw_story200553_tc01_node",
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
        missing_rules = self._check_all_expected_rules_are_applied(
            all_nodes, iptables, rule_set)
        missing_rules_node = self._check_all_expected_rules_are_applied(
            node_1, iptables, rule_set_node)

        for rules in missing_rules, missing_rules_node:
            self._assert_rules_applied(rules)

    #@attr('pre-reg', 'revert', 'story200553', 'story200553_tc03')
    def obsolete_35_p_export_load_string_algo_rules(self):
        """
        Obsoleted as functionality moved to ATs:
            ERIClitplinuxfirewall:
                test_35_p_export_load_string_algo_rules.at

        @#tms_id: torf_200553_tc03
        @#tms_requirements_id: TORF-200553
        @#tms_title: Test exporting/loading the firewal rules rules with
         STRING and ALGO properties and with negated source property and with
         action=REJECT
        @#tms_description: Test to verify that user can export/load firewall
        rules with new properties STRING and ALGO and with supported negation
        of SOURCE property and action=REJECT. Check that user can export/load
        rules with state=none(TORF-214102)
        @#tms_test_steps:
            @step: Create firewall rules to be used in this test
            @result: firewall rules created
            @step: Run litp export command on newly created rules
            @result: Rules are exported
            @step: Compare the exported xml with templates
            @result: Rules are exported properly
            @step: Remove the rules from model
            @result: Rules are removed
            @step: Load the rules from xmls exported earlier
            @result: Rules are loaded
            @step: Create and run plan
            @result: Plan is created and runs successfully
         @#tms_test_precondition:NA
        @#tms_execution_type: Automated
        """
        xml_filenames = \
            ['xml_node_fw_rules_1_story200553.xml',
             'xml_node_fw_rules_2_story200553.xml',
             'xml_node_fw_rules_3_story214102.xml']
        local_filepath = os.path.dirname(__file__)
        for xml_filename in xml_filenames:
            local_xml_filepath = local_filepath + "/xml_files/" + xml_filename
            xml_filepath = "/tmp/" + xml_filename
            self.assertTrue(self.copy_file_to(
                self.ms1, local_xml_filepath, xml_filepath,
                root_copy=True), "The file copy failed")
        rule_names = ["fw_200553_1", "fw_200553_2", "fw_214102_1"]

        # Find node1 path
        node1_path = self.find(self.ms1, "/deployments", "node", True)[0]

        # Find node1 cluster config already in model
        fw_node_config = self.find(
            self.ms1, node1_path, "firewall-node-config")[0]
        node_rules_collection = self.find(self.ms1, fw_node_config,
                                          "collection-of-firewall-rule")[0]
        self.log('info',
                 '1. Create firewall rules to be used in this test')
        props = ['name="032 test1" dport=9200 proto=tcp provider=iptables'
                 ' source="!192.168.0.0/20" string="test" algo=bm',
                 'name="034 test1" dport=9200 proto=tcp provider=iptables'
                 ' source="!192.168.0.55" string="test"'
                 ' algo=kmp action=reject',
                 'name="090 test" sport=110 dport=9200 state=none']
        for i in range(0, 3):
            self._create_fw_rule_item(fw_node_config, rule_names[i], props[i])

        rule_1 = '{0}/rules/{1}'.format(fw_node_config, rule_names[0])
        rule_2 = '{0}/rules/{1}'.format(fw_node_config, rule_names[1])
        rule_3 = '{0}/rules/{1}'.format(fw_node_config, rule_names[2])

        rules_temp_files = ["/tmp/xml_exported_200553_1.xml",
                            "/tmp/xml_exported_200553_2.xml",
                            "/tmp/xml_exported_214102.xml"]

        self.log('info',
                 '2. Export the created firewall rules')
        self.execute_cli_export_cmd(self.ms1, rule_1,
                                    rules_temp_files[0])

        self.execute_cli_export_cmd(self.ms1, rule_2,
                                    rules_temp_files[1])

        self.execute_cli_export_cmd(self.ms1, rule_3,
                                    rules_temp_files[2])
        self.log('info',
                 '3. Verify the rules are exported correctly')
        template_files = ["/tmp/xml_node_fw_rules_1_story200553.xml",
                          "/tmp/xml_node_fw_rules_2_story200553.xml",
                          "/tmp/xml_node_fw_rules_3_story214102.xml"]

        for i in range(0, 3):
            compare_cmd = "diff -w {0} {1} ".format(rules_temp_files[i],
                                                    template_files[i])
            stdout, _, _ = self.run_command(self.ms1, compare_cmd)
            self.assertEqual([], stdout)

        self.log('info', '4. Remove the created rules')
        for rule in rule_names:
            self._remove_fw_rule(fw_node_config, rule)

        self.log('info', '5. Load the rules from xml')
        for xml in rules_temp_files:
            self.execute_cli_load_cmd(self.ms1, node_rules_collection, xml)

        self.log('info', '6. Create and run plan')
        self._create_run_and_wait_for_plan_state(test_constants.PLAN_COMPLETE,
                                                 'Plan to load firewall'
                                                 ' rules failed')

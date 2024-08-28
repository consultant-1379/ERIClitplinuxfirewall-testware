"""
COPYRIGHT Ericsson 2019
The copyright to the computer program(s) herein is the property of
Ericsson Inc. The programs may be used and/or copied only with written
permission from Ericsson Inc. or in accordance with the terms and
conditions stipulated in the agreement/contract under which the
program(s) have been supplied.

@since:     July 2017
@author:    Paul Carroll
@summary:   Agile: TORF-199859
"""
import test_constants
from litp_generic_test import GenericTest, attr


class Story199859(GenericTest):
    """
    Assure Streaming applications need SNAT firewall rules in order to set the
    --to-source of the stream ACK packets to be the same as the nodes stream
    target i.e. the LVS router proxying the public address exposed to the
    nodes.
    """

    def setUp(self):
        """
        Description:
            -
        Actions:
            -
        Results:
            -
        """
        self.dummy_for_pylint_obsoletion = attr()
        super(Story199859, self).setUp()
        self.ms_node = self.get_management_node_filename()
        node_urls = self.find(self.ms_node, '/deployments', 'node')
        self.n1_vpath = node_urls[0]
        self.n2_vpath = node_urls[1]
        self.n1_hostname = self.get_node_hostname(self.n1_vpath)
        self.n2_hostname = self.get_node_hostname(self.n2_vpath)
        self.ms_hostname = self.get_node_hostname('/ms')

        self.internal_subnet = '100.100.100.0/24'
        self.storage_subnet = '200.200.200.0/24'
        self.tosource_1 = '200.200.200.130'
        self.tosource_2 = '200.200.200.160'

        self.provider_ipv4 = 'iptables'
        self.table_nat = 'nat'
        self.protocols = ['tcp', 'udp']

    def tearDown(self):
        """
        Description:
            -
        Actions:
            -
        Results:
            -
        """
        super(Story199859, self).tearDown()

    def get_node_hostname(self, node_vpath):
        """
        Get the hostname of a modeled node.

        Args:
            node_vpath (str): Model path of the node

        Results:
            Hostname of the node
        """
        taf_hostname = self.get_node_filename_from_url(
                self.ms_node, node_vpath)
        return self.get_node_att(taf_hostname, 'hostname')

    def _execute_create_run_plan(self):
        """
        Create and run a plan
        """
        self.execute_cli_createplan_cmd(self.ms_node)
        self.execute_cli_showplan_cmd(self.ms_node)
        self.execute_cli_runplan_cmd(self.ms_node)

    def _execute_create_run_plan_assert_plan_successful(self):
        """
        Create and run a plan and wait for it to finish successfully.
        """
        self._execute_create_run_plan()
        self.assertTrue(self.wait_for_plan_state(
                self.ms_node, test_constants.PLAN_COMPLETE, timeout_mins=5),
                'The plan execution did not succeed')

    @staticmethod
    def _rule_line_to_map(rule):
        """
        Convert an iptables output line to a map of key values.

        Args:
            rule (str): Output line from iptables command e.g:
                -A FORWARD -p tcp -m tcp --dport 3389 -j ACCEPT

        Results:
            Map of line output e.g:
            {'-A': 'FORWARD', '-p': 'tcp', '--dport': '3389', '-j': 'ACCEPT'}
        """
        maapp = {}
        tokens = rule.split()
        _optionflag = None
        _optionvalue = ''
        for tkn in tokens:
            if tkn.startswith('-'):
                if _optionflag is not None:
                    maapp[_optionflag.strip()] = _optionvalue.strip()
                    _optionvalue = ''
                    _optionflag = None
                _optionflag = tkn
            else:
                _optionvalue += ' ' + tkn
        if _optionflag is not None:
            maapp[_optionflag.strip()] = _optionvalue.strip()
        return maapp

    def _find_rule(self, rules, rule_name):
        """
        Find a rule by the comment string

        Args:
             rules (str[]): iptables rules to search
             rule_name (str): Rule comment to match

        Results:
            The matching rule from iptables or None if nothing found.
        """
        regex = '--comment "{0}"'.format(rule_name)
        self.log('info', 'Searching for [{0}]'.format(regex))
        for rule in rules:
            if regex in rule:
                self.log('info', 'Found a rule match with [{0}]'.format(rule))
                return self._rule_line_to_map(rule)
        return None

    def _get_node_applied_rules(self, provider, table, hostname):
        """
        Get the iptables rules

        Args:
             provider (str): iptables
             table (str): iptables table
             hostname (str): Host to get the rules from

        Results:
            iptables rules on the node.
        """
        cmd = '/sbin/{0} -S --table {1}'.format(provider, table)
        self.log('info',
                 '"{0}" firewall configuration "{1}"'.
                 format(provider, hostname))

        rules = self.run_command(hostname,
                                 cmd, su_root=True,
                                 default_asserts=True)[0]
        return rules

    def assert_rule(self, applied_rule, expected):
        """
        Assert an iptables rule if applied as expected.

        Args:
            applied_rule (map): Applied rule from a node
            expected (map): Expected values.
        """
        self.assertEqual(expected['target'], applied_rule['-j'])
        self.assertEqual(expected['protocol'], applied_rule['-p'])
        self.assertEqual('POSTROUTING', applied_rule['-A'])
        self.assertEqual(expected['tosource'], applied_rule['--to-source'])
        self.assertEqual(expected['source'], applied_rule['-s'])
        self.assertEqual(expected['destination'], applied_rule['-d'])

    @staticmethod
    def _get_fwrule_properties(rule_name, provider, jump, chain, table,
                               protocol, source, destination, tosource):
        """
        Get the properties to create a firewall-rule in LITP

        Args:
            rule_name (str): The rule name (comment)
            provider (str): Rule provider (iptables/ip6tables)
            jump (str): jump
            chain (str): chain
            table (str): table
            protocol (str): protocol
            source (str): source
            destination (str): destination
            tosource (str): tosource

        Results:
            Property string to use to create the firewall-rule in LITP
        """
        props = 'provider={provider} name="{name}" jump="{jump}" ' \
                'chain="{chain}" ' \
                'source="{source}" destination="{destination}" ' \
                'proto={proto} table={table} ' \
                'tosource={tosource}'.format(provider=provider,
                                             name=rule_name,
                                             jump=jump,
                                             chain=chain,
                                             source=source,
                                             destination=destination,
                                             tosource=tosource,
                                             table=table,
                                             proto=protocol)
        return props

    def _create_snat_rule(self, vpath, proto, provider, rule_index,
                          tosource, expected_results,
                          record_delete_paths=None):
        """
        Create a SNAT rule.

        Args:
            vpath (str): Location to create the rule
            proto (str): ipv4
            provider (str): iptables
            rule_index (int): Rule index
            tosource (str): tosource address
            expected_results (map): Map to append the expected outcome to.
            record_delete_paths (str[]): List to add the created rule path to
        """
        rule_name = '{0} SNAT {1}'.format(rule_index, proto)
        rule_props = self._get_fwrule_properties(
                rule_name, provider, 'SNAT', 'POSTROUTING',
                self.table_nat, proto, self.internal_subnet,
                self.storage_subnet, tosource)

        create_vpath = vpath + '/fw_snat_{0}_story199859'.format(proto)
        self.execute_cli_create_cmd(
                self.ms_node,
                create_vpath,
                'firewall-rule', rule_props)

        if record_delete_paths is not None:
            record_delete_paths.append(create_vpath)
        expected_results[rule_name] = {
            'target': 'SNAT',
            'protocol': proto,
            'chain': 'POSTROUTING',
            'tosource': tosource,
            'source': self.internal_subnet,
            'destination': self.storage_subnet,
            'comment': '{0} ipv4'.format(rule_name)
        }

    def assert_applied_rules(self, hostname, expected):
        """
        Assert all expected rules have been created/updates.

        Args:
            hostname (str): The host to check
            expected (map): Collection of rules to check have been
            created/updated
        """
        rules = self._get_node_applied_rules(self.provider_ipv4,
                                             self.table_nat,
                                             hostname)
        for e_rule_name, expected in expected.items():
            self.log('info', 'Asserting rule [{0}] -> [{1}]'.format(
                    e_rule_name, expected))
            test_rule = self._find_rule(rules, expected['comment'])
            self.assert_rule(test_rule, expected)

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
        self.poweroff_peer_node(self.ms_node, reboot_system)
        self.log('info', 'Powered off {0}, powring on.'.format(reboot_system))
        self.poweron_peer_node(self.ms_node, reboot_system)
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
        self.assertEqual(0, exit_code,
                         msg='Timedout waiting for {0} to join '
                             'cluster!'.format(reboot_system))

        self.log('info', 'VCS system started, waiting for groups.')
        self.wait_for_all_starting_vcs_groups(self.n1_hostname,
                                              group_timeout_mins)

    def _stop_plan_after_task(self, rule_name, task_node):
        """
        Stop a plan once a fireeall task has been applied on a node.

        Args:
            rule_name (str): The firewall rule comment string
            task_node (str): The node the task was generated for

        Results:
            The task description in the plan.
        """
        wait_for_task = 'Add firewall rule "{0}" on node "{1}"'.format(
                rule_name, task_node)
        self.assertTrue(self.wait_for_task_state(self.ms_node,
                                                 wait_for_task,
                                                 test_constants.
                                                 PLAN_TASKS_SUCCESS,
                                                 False,
                                                 timeout_mins=5),
                        'The peer node is is not updated')
        self.log('info', 'Restarting litpd.')
        self.restart_litpd_service(self.ms_node)
        self.log('info', 'litpd restarted, waiting for plan to go to state'
                         ' Stopped(up to 10 mins).')
        self.wait_for_plan_state(self.ms_node, test_constants.PLAN_STOPPED,
                                 timeout_mins=10)
        self.log('info', 'Plan should now be Stopped.')
        return wait_for_task

    #@attr('pre-reg', 'revert', 'story199859', 'story199859_tc01')
    def obsolete_01_p_snat_rules_node(self):
        """
        Obsoleted as functionality moved to test_02_p_create_rules and
        test_03_p_update_remove_rules in testset_firewall_rule_positive.py

        @#tms_id: torf_199859_tc01
        @#tms_requirements_id: TORF-199859
        @#tms_title: Create/Modify/Delete SNAT tcp/udp IPV4 rules.
        @#tms_description: With an already up and running LITP environment,
         create, update and delete SNAT rules on the MS, at cluster level and
         node level.
        @#tms_test_steps:
            @step: Create SNAT TCP IPV4 rule on MS
            @result: The Litp items are created.
            @step: Create SNAT UDP IPV4 rule on MS
            @result: The Litp items are created.
            @step: Create SNAT TCP IPV4 rule on node1
            @result: The Litp items are created.
            @step: Create SNAT UDP IPV4 rule on node1
            @result: The Litp items are created.
            @step: Create SNAT TCP IPV4 rule on cluster c1
            @result: The Litp items are created.
            @step: Create SNAT UDP IPV4 rule on cluster c1
            @result: The Litp items are created.
            @step: Create and run a plan
            @result: The plan is successful.
            @step: Check the TCP and UDP rules have been applied to node1
            @result: Verify 4 SNAT rules have been applied to node1
            @step: Check the TCP and UDP rules have been applied to the MS
            @result: Verify 2 SNAT rules have been applied to node1
            @step: Update all created rules and change the tosource property
            @result: The Litp items are updated.
            @step: Create and run a plan
            @result: The plan is successful.
            @step: Check the TCP and UDP rules have been updated to node1
            @result: Verify 4 SNAT rules have been updated to reflect the
             updated tosource address.
            @step: Check the TCP and UDP rules have been applied to the MS
            @result: Verify 2 SNAT rules have been updated to reflect the
             updated tosource address.
            @step: Delete all created SNAT rules.
            @result: The Litp items are for removal.
            @step: Create and run a plan
            @result: The plan is successful.
            @step: Check the TCP and UDP SNAT rules are deleted from node1
            @result: No TCP or UDP rules exist in the iptables configuration.
            @step: Check the TCP and UDP SNAT rules are deleted from the MS
            @result: No TCP or UDP rules exist in the iptables configuration.
        @#tms_test_precondition: NA
        @#tms_execution_type: Automated
        """
        fw_rules_node_vpath = '{0}/rules'.format(
                self.find(self.ms_node, self.n1_vpath,
                          'firewall-node-config')[0])

        fw_rules_ms_vpath = '{0}/rules'.format(
                self.find(self.ms_node, '/ms', 'firewall-node-config')[0])

        fw_rules_cluster_vpath = '{0}/rules'.format(
                self.find(self.ms_node, '/deployments',
                          'firewall-cluster-config')[0]
        )

        rule_index = 9000
        step_id = 1

        created_rules = []
        expected_node_applied = {}
        expected_ms_applied = {}
        for proto in self.protocols:
            self.log('info', '#{0}. Create MS SNAT {1} rule'.format(
                    step_id, proto))
            self._create_snat_rule(fw_rules_ms_vpath, proto,
                                   self.provider_ipv4,
                                   rule_index + step_id,
                                   self.tosource_1,
                                   expected_ms_applied,
                                   created_rules)
            step_id += 1

        for proto in self.protocols:
            self.log('info',
                     '#{0}. Create node level SNAT {1} rule on node1'.format(
                             step_id, proto))
            self._create_snat_rule(fw_rules_node_vpath, proto,
                                   self.provider_ipv4,
                                   rule_index + step_id,
                                   self.tosource_1,
                                   expected_node_applied,
                                   created_rules)
            step_id += 1

        for proto in self.protocols:
            self.log('info',
                     '#{0}. Create cluster level SNAT {1} rule'.format(
                             step_id, proto))
            self._create_snat_rule(fw_rules_cluster_vpath, proto,
                                   self.provider_ipv4,
                                   rule_index + step_id,
                                   self.tosource_1,
                                   expected_node_applied,
                                   created_rules)
            step_id += 1

        self.log('info', '#7. Create and run plan to completion')
        self._execute_create_run_plan_assert_plan_successful()

        self.log('info', '#8. Assert applied rules on node1')
        self.assert_applied_rules(self.n1_hostname, expected_node_applied)

        self.log('info', '#9. Assert applied rules on MS')
        self.assert_applied_rules(self.ms_hostname, expected_ms_applied)

        self.log('info', '#10. Update tosource property on all created rules.')
        for vpath in created_rules:
            self.execute_cli_update_cmd(
                    self.ms_node, vpath, 'tosource=' + self.tosource_2)
        for erule in expected_ms_applied.values():
            erule['tosource'] = self.tosource_2
        for erule in expected_node_applied.values():
            erule['tosource'] = self.tosource_2

        self.log('info', '#11. Create and run plan to completion')
        self._execute_create_run_plan_assert_plan_successful()

        self.log('info', '#12. Assert updates applied to rules on MS')
        self.assert_applied_rules(self.ms_hostname, expected_ms_applied)

        self.log('info', '#13. Assert updates applied to rules on node1')
        self.assert_applied_rules(self.n1_hostname, expected_node_applied)

        self.log('info', '#14. Delete all created SNAT rules')
        for vpath in created_rules:
            self.execute_cli_remove_cmd(self.ms_node, vpath)

        self.log('info', '#15. Create and run plan to completion')
        self._execute_create_run_plan_assert_plan_successful()

        self.log('info', '#16. Assert rules on node1 have been deleted.')
        rules_node = self._get_node_applied_rules(self.provider_ipv4,
                                                  self.table_nat,
                                                  self.n1_hostname)
        for test_rule in expected_node_applied.values():
            rule = self._find_rule(rules_node, test_rule['comment'])
            self.assertEqual(None, rule)

        self.log('info', '#17. Assert rules on MS have been deleted.')
        rules_ms = self._get_node_applied_rules(self.provider_ipv4,
                                                self.table_nat,
                                                self.ms_hostname)
        for test_rule in expected_ms_applied.values():
            rule = self._find_rule(rules_ms, test_rule['comment'])
            self.assertEqual(None, rule)

        self.log('info', '#18. Testcase complete.')

    #@attr('pre-reg', 'revert', 'story199859', 'story199859_tc02')
    def obsolete_02_p_snat_rules_persistence_idempotent(self):
        """
        Obsoleted as functionality moved to test_02_p_create_rules and
        test_03_p_update_remove_rules in testset_firewall_rule_positive.py

        @#tms_id: torf_199859_tc02
        @#tms_requirements_id: TORF-199859
        @#tms_title: Create a SNAT firewall rules on 2 nodes and verify the
         idempotent of the tasks generated and the persistence of the changes
         applied.
        @#tms_description: With an already up and running LITP environment,
         create a SNAT firewall rule on nodee node1 and node2. Once the tasks
         for node1 are applied, restart litpd to stop the plan. Create another
         plan and verify those node1 tasks are not created. Execute the plan
         to completion. Once complete, reboot node1 and verify applied firewall
         rules are still defined in iptables. Do the same for node2
        @#tms_test_steps:
            @step: Create SNAT TCP IPV4 rules on node1 and node2
            @result: The Litp items are created.
            @step: Create and run a plan
            @result: The plan is in a Running state
            @step: Restart litpd once the generated task for node1 has been
             applied.
            @result: Plan is in a Stopped state.
            @step: Create another plan and check that no tasks for node1 were
             created
            @result: Only tasks for node2 show in the plan
            @step: Run the plan and wait for it to complete.
            @result: Plan completes successfully.
            @step: Check the firewall rule is defined in iptables on both node1
             and node2
            @result: Both node1 and node2 have the SNAT firewall rule defined
             in iptables.
            @step: Reboot node1
            @result: node1 has rebooted and any VCS groups are RUNNING
            @step: Check the firewall rule is still configured in iptables
            @result: iptables has the expected SNAT rule
            @step: Reboot node2
            @result: node2 has rebooted and any VCS groups are RUNNING
            @step: Check the firewall rule is still configured in iptables
            @result: iptables has the expected SNAT rule
        # @#tms_test_precondition: NA
        # @#tms_execution_type: Automated
        """
        fw_rules_n1_vpath = '{0}/rules'.format(
                self.find(self.ms_node, self.n1_vpath,
                          'firewall-node-config')[0])
        fw_rules_n2_vpath = '{0}/rules'.format(
                self.find(self.ms_node, self.n2_vpath,
                          'firewall-node-config')[0])
        rule_id_node1 = 405
        rule_id_node2 = 406

        expected_n1_applied = {}
        expected_n2_applied = {}

        self.log('info', '# 1. Create a SNAT rule on node1 and node2')
        self._create_snat_rule(fw_rules_n1_vpath, 'tcp',
                               self.provider_ipv4,
                               rule_id_node1,
                               self.tosource_1,
                               expected_n1_applied)
        self._create_snat_rule(fw_rules_n2_vpath, 'tcp',
                               self.provider_ipv4,
                               rule_id_node2,
                               self.tosource_1,
                               expected_n2_applied)

        self.log('info', '# 2.Create a plan and run it')
        self._execute_create_run_plan()

        rule_name = '{0} SNAT tcp'.format(rule_id_node1)
        self.log('info', '# 3.Stop the plan after the firewall task '
                         'for rule "{0}" has been applied to '
                         '{1}'.format(rule_name, self.n1_hostname))
        wait_for_task = self._stop_plan_after_task(rule_name, self.n1_hostname)

        self.log('info', '# 4. Recreate the plan and verify the applied '
                         'firewall configuration is not present in the new '
                         'plan.')
        self.execute_cli_createplan_cmd(self.ms_node)
        self.execute_cli_showplan_cmd(self.ms_node)
        self.assertEqual(
                test_constants.CMD_ERROR,
                self.get_task_state(self.ms_node, wait_for_task, False))

        self.log('info', '# 5.Run the plan and wait for it to complete.')
        self.execute_cli_runplan_cmd(self.ms_node)
        self.assertTrue(self.wait_for_plan_state(self.ms_node,
                                                 test_constants.
                                                 PLAN_COMPLETE,
                                                 timeout_mins=5),
                        'The plan execution did not succeed')

        self.log('info', '# 6. Assert rules are applied on node1 and node2')
        self.assert_applied_rules(self.n1_hostname, expected_n1_applied)
        self.assert_applied_rules(self.n2_hostname, expected_n2_applied)

        self.log('info', '# 7. Reboot node1.')
        self._vcs_reboot_and_wait_for_system(self.n2_hostname,
                                             self.n1_hostname)

        self.log('info', '# 8. Assert rules are still applied on node1')
        self.assert_applied_rules(self.n1_hostname, expected_n1_applied)

        self.log('info', '# 9. Reboot node2.')
        self._vcs_reboot_and_wait_for_system(self.n1_hostname,
                                             self.n2_hostname)

        self.log('info', '# 10. Assert rules are still applied on node2')
        self.assert_applied_rules(self.n2_hostname, expected_n2_applied)

        self.log('info', '# 11. Testcase complete.')

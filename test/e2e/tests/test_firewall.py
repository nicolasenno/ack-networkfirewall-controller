# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the
# License is located at
#
# 	 http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

"""Integration tests for the Network Firewall API.
"""

import pytest
import time

from acktest.resources import random_suffix_name
from acktest.k8s import resource as k8s
from e2e import service_marker, CRD_GROUP, CRD_VERSION, load_networkfirewall_resource
from e2e.replacement_values import REPLACEMENT_VALUES
from e2e.bootstrap_resources import get_bootstrap_resources
from e2e.tests.helper import NetworkFirewallValidator

RESOURCE_PLURAL = "firewalls"

CREATE_WAIT_AFTER_SECONDS = 10
UPDATE_WAIT_AFTER_SECONDS = 30
# It takes really long for firewall to be created/deleted.
TIMEOUT_SECONDS = 1000

@pytest.fixture
def simple_firewall(request, simple_firewall_policy):
    resource_name = random_suffix_name("firewall-ack-test", 24)
    resources = get_bootstrap_resources()

    (_, policy_cr) = simple_firewall_policy
    policy_status = policy_cr["status"]
    policy_resp = policy_status["firewallPolicyResponse"]
    policy_arn = policy_resp["firewallPolicyARN"]
    subnet_id = resources.SharedTestVPC.public_subnets.subnet_ids[0]


    replacements = REPLACEMENT_VALUES.copy()
    replacements["FIREWALL_NAME"] = resource_name
    replacements["VPC_ID"] = resources.SharedTestVPC.vpc_id
    replacements["SUBNET_ID"] = subnet_id
    replacements["LOG_DESTINATION_TYPE"] = "S3"
    replacements["LOG_DESTINATION"] = resources.LogsBucket.name
    replacements["TRAFFIC_TYPE"] = "ALL"
    replacements["FIREWALL_POLICY_ARN"] = policy_arn

    # Load Network Firewall CR
    resource_data = load_networkfirewall_resource(
        "firewall",
        additional_replacements=replacements,
    )

    # Create k8s resource
    ref = k8s.CustomResourceReference(
        CRD_GROUP,
        CRD_VERSION,
        RESOURCE_PLURAL,
        resource_name,
        namespace="default",
    )
    k8s.create_custom_resource(ref, resource_data)

    time.sleep(CREATE_WAIT_AFTER_SECONDS)

    # Get latest Network Firewall CR
    cr = k8s.wait_resource_consumed_by_controller(ref)

    assert cr is not None
    assert k8s.get_resource_exists(ref)

    yield (ref, cr)

    # Try to delete, if doesn't already exist
    try:
        _, deleted = k8s.delete_custom_resource(ref, 3, 10)
        assert deleted
    except:
        pass

@pytest.fixture
def simple_firewall_policy(request):
    resource_name = random_suffix_name("fw-pol-ack-test", 24)

    replacements = REPLACEMENT_VALUES.copy()
    replacements["FIREWALL_POLICY_NAME"] = resource_name
    replacements["STATEFUL_DEFAULT_ACTION"] = "aws:drop_established"
    replacements["RULE_ORDER"] = "STRICT_ORDER"
    replacements["STREAM_EXCEPTION_POLICY"] = "DROP"
    replacements["STATELESS_DEFAULT_ACTION"] = "aws:drop"
    replacements["STATELESS_FRAG_DEFAULT_ACTION"] = "aws:forward_to_sfe"

    # Load Firewall Policy CR
    resource_data = load_networkfirewall_resource(
        "firewall_policy",
        additional_replacements=replacements,
    )

    # Create k8s resource
    ref = k8s.CustomResourceReference(
        CRD_GROUP,
        CRD_VERSION,
        "firewallpolicies",
        resource_name,
        namespace="default",
    )
    k8s.create_custom_resource(ref, resource_data)

    time.sleep(CREATE_WAIT_AFTER_SECONDS)

    # Get latest Firewall Policy CR
    cr = k8s.wait_resource_consumed_by_controller(ref)

    assert cr is not None
    assert k8s.get_resource_exists(ref)

    yield (ref, cr)

    # Try to delete, if doesn't already exist
    try:
        _, deleted = k8s.delete_custom_resource(ref, 3, 10)
        assert deleted
    except:
        pass


@service_marker
@pytest.mark.canary
class TestNetworkFirewall:
    def test_create_delete(self, networkfirewall_client, simple_firewall):
        (fw, cr) = simple_firewall

        firewall_config = cr["status"]["firewall"]
        firwall_name = firewall_config["firewallName"]

        networkfirewall_validator = NetworkFirewallValidator(networkfirewall_client)
        # Check Network Firewall comes to READY state
        networkfirewall_validator.wait_for_firewall_creation_or_die(firwall_name, "READY", TIMEOUT_SECONDS)

        # Check Network Firewall logging configuration exist in AWS
        networkfirewall_validator.assert_network_firewall_logs(firwall_name, 1)

        # Remove Network Firewall logging configuration
        updates = {
            "spec": {
                "loggingConfiguration": None
            }
        }

        k8s.patch_custom_resource(fw, updates)
        time.sleep(UPDATE_WAIT_AFTER_SECONDS)
        networkfirewall_validator.assert_network_firewall_logs(firwall_name, 0)

        # Update Network Firewall logging configuration
        resources = get_bootstrap_resources()
        updates = {
            "spec": {
                "loggingConfiguration": {
                    "logDestinationConfigs": [
                        {
                            "logDestination": {
                                "bucketName": resources.LogsBucket.name
                            },
                            "logDestinationType": "S3",
                            "logType": "ALERT"
                        },
                        {
                            "logDestination": {
                                "bucketName": resources.LogsBucket.name
                            },
                            "logDestinationType": "S3",
                            "logType": "FLOW"
                        }
                    ]
                }
            }
        }

        k8s.patch_custom_resource(fw, updates)
        time.sleep(UPDATE_WAIT_AFTER_SECONDS)
        networkfirewall_validator.assert_network_firewall_logs(firwall_name, 2)

        # Delete k8s resource
        k8s.delete_custom_resource(fw)

        # Check Firewall no longer exists in AWS
        networkfirewall_validator.wait_for_firewall_deletion_or_die(firwall_name, TIMEOUT_SECONDS)

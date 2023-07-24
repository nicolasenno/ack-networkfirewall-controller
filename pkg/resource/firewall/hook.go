// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package firewall

import (
	"context"
	"fmt"
	"reflect"
	"sort"

	"github.com/pkg/errors"

	svcapitypes "github.com/aws-controllers-k8s/networkfirewall-controller/apis/v1alpha1"
	ackcompare "github.com/aws-controllers-k8s/runtime/pkg/compare"
	ackrequeue "github.com/aws-controllers-k8s/runtime/pkg/requeue"
	ackrtlog "github.com/aws-controllers-k8s/runtime/pkg/runtime/log"
	svcsdk "github.com/aws/aws-sdk-go/service/networkfirewall"
)

var (
	resourceName = GroupKind.Kind

	requeueWaitWhileDeleting = ackrequeue.NeededAfter(
		errors.New(resourceName+" is Deleting."),
		ackrequeue.DefaultRequeueAfterDuration,
	)

	ErrSyncingPutProperty = errors.New("Error syncing property LoggingConfiguration")
)

// createLoggingConfig creates logging config for a firewall.
func (rm *resourceManager) createLoggingConfig(
	ctx context.Context,
	r *resource,
) (err error) {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.createLoggingConfig")
	defer exit(err)

	if r.ko.Spec.LoggingConfiguration != nil {
		if err = rm.syncLoggingConfiguration(ctx, r, nil); err != nil {
			return fmt.Errorf("%v: %v", err, ErrSyncingPutProperty)
		}
	}
	return nil
}

// deleteLoggingConfig deletes logging config from a firewall. It is necessary
// to delete logging config prior to the deletion of firewall.
func (rm *resourceManager) deleteLoggingConfig(
	ctx context.Context,
	r *resource,
) (err error) {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.deleteLoggingConfig")
	defer exit(err)

	if r.ko.Spec.LoggingConfiguration != nil {
		if err = rm.syncLoggingConfiguration(ctx, nil, r); err != nil {
			return fmt.Errorf("%v: %v", err, ErrSyncingPutProperty)
		}
	}
	return nil
}

// customUpdateFirewall patches each of the resource properties in the backend AWS
// service API and returns a new resource with updated fields.
func (rm *resourceManager) customUpdateFirewall(
	ctx context.Context,
	desired *resource,
	latest *resource,
	delta *ackcompare.Delta,
) (updated *resource, err error) {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.customUpdateFirewall")
	defer exit(err)

	// Merge in the information we read from the API call above to the copy of
	// the original Kubernetes object we passed to the function
	ko := desired.ko.DeepCopy()

	rm.setStatusDefaults(ko)

	if delta.DifferentAt("Spec.LoggingConfiguration") {
		if err := rm.syncLoggingConfiguration(ctx, desired, latest); err != nil {
			return nil, fmt.Errorf("%v: %v", err, ErrSyncingPutProperty)
		}
	}

	return &resource{ko}, nil
}

// addPutFieldsToSpec will describe logging config and add its
// returned values to the Firewall spec.
func (rm *resourceManager) addLoggingConfigToSpec(
	ctx context.Context,
	r *resource,
	ko *svcapitypes.Firewall,
) (err error) {
	getLoggingConfigurationResponse, err := rm.sdkapi.DescribeLoggingConfigurationWithContext(ctx, rm.getLoggingConfigurationPayload(r))
	if err != nil {
		return err
	}
	ko.Spec.LoggingConfiguration = rm.setResourceLoggingConfiguration(r, getLoggingConfigurationResponse)
	return nil
}

func customPreCompare(
	a *resource,
	b *resource,
) {
	if a.ko.Spec.LoggingConfiguration == nil && b.ko.Spec.LoggingConfiguration == nil {
		return
	}

	if a.ko.Spec.LoggingConfiguration == nil {
		a.ko.Spec.LoggingConfiguration = &svcapitypes.LoggingConfiguration{}
	}

	if b.ko.Spec.LoggingConfiguration == nil {
		b.ko.Spec.LoggingConfiguration = &svcapitypes.LoggingConfiguration{}
	}

	sort.Slice(a.ko.Spec.LoggingConfiguration.LogDestinationConfigs[:], func(i, j int) bool {
		return *a.ko.Spec.LoggingConfiguration.LogDestinationConfigs[i].LogType < *a.ko.Spec.LoggingConfiguration.LogDestinationConfigs[j].LogType
	})
	sort.Slice(b.ko.Spec.LoggingConfiguration.LogDestinationConfigs[:], func(i, j int) bool {
		return *b.ko.Spec.LoggingConfiguration.LogDestinationConfigs[i].LogType < *b.ko.Spec.LoggingConfiguration.LogDestinationConfigs[j].LogType
	})
}

func (rm *resourceManager) getLoggingConfigurationPayload(
	r *resource,
) *svcsdk.DescribeLoggingConfigurationInput {
	res := &svcsdk.DescribeLoggingConfigurationInput{}
	res.SetFirewallName(*r.ko.Spec.FirewallName)
	return res
}

func (rm *resourceManager) newLoggingConfigurationPayload(
	r *resource,
) *svcsdk.UpdateLoggingConfigurationInput {
	res := &svcsdk.UpdateLoggingConfigurationInput{}
	res.SetFirewallName(*r.ko.Spec.FirewallName)
	if r.ko.Spec.LoggingConfiguration != nil {
		res.SetLoggingConfiguration(rm.newLoggingConfiguration(r))
	} else {
		res.SetLoggingConfiguration(&svcsdk.LoggingConfiguration{})
	}
	return res
}

func makeLogDestinationConfigMapKey(cfg *svcapitypes.LogDestinationConfig) string {
	keys := make([]string, 0, len(cfg.LogDestination))
	for k := range cfg.LogDestination {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	key := "LogDestination:"
	for _, k := range keys {
		v := *cfg.LogDestination[k]
		key += fmt.Sprintf("%s:%s,", k, v)
	}

	if cfg.LogDestinationType != nil {
		key += fmt.Sprintf("LogDestinationType:%s,", *cfg.LogDestinationType)
	}
	if cfg.LogType != nil {
		key += fmt.Sprintf("LogType:%s", *cfg.LogType)
	}
	return key
}

func makeLogDestinationConfigMap(logDestinationConfig []*svcapitypes.LogDestinationConfig) map[string]*svcapitypes.LogDestinationConfig {
	logDestinationConfigMap := make(map[string]*svcapitypes.LogDestinationConfig)

	for _, cfg := range logDestinationConfig {
		logDestinationConfigMap[makeLogDestinationConfigMapKey(cfg)] = cfg
	}
	return logDestinationConfigMap
}

// compareLoggingDestinationConfigs generates LogDestinationConfigs which need to be
// added and deleted to reach desired LogDestinationConfig from latest LogDestinationConfig
func compareLoggingDestinationConfigs(desired []*svcapitypes.LogDestinationConfig, latest []*svcapitypes.LogDestinationConfig) (add []*svcapitypes.LogDestinationConfig, delete []*svcapitypes.LogDestinationConfig) {
	add = make([]*svcapitypes.LogDestinationConfig, 0)
	delete = make([]*svcapitypes.LogDestinationConfig, 0)

	desiredMap := makeLogDestinationConfigMap(desired)
	latestMap := makeLogDestinationConfigMap(latest)

	for key, val := range desiredMap {
		if _, ok := latestMap[key]; !ok {
			add = append(add, val)
		}
	}

	for key, val := range latestMap {
		if _, ok := desiredMap[key]; !ok {
			delete = append(delete, val)
		}
	}

	return add, delete
}

// syncLoggingConfiguration gets desired logging config and latest (existing)
// logging config as input. It compares both and applies the delta to ensure
// desired logging config is configured for the firewall.
func (rm *resourceManager) syncLoggingConfiguration(
	ctx context.Context,
	desired *resource,
	latest *resource,
) (err error) {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.syncLoggingConfiguration")
	defer exit(err)

	var input *svcsdk.UpdateLoggingConfigurationInput
	var add, delete []*svcapitypes.LogDestinationConfig
	if latest != nil && desired != nil {
		add, delete = compareLoggingDestinationConfigs(desired.ko.Spec.LoggingConfiguration.LogDestinationConfigs, latest.ko.Spec.LoggingConfiguration.LogDestinationConfigs)
		input = rm.newLoggingConfigurationPayload(latest)
	} else if latest == nil {
		add = desired.ko.Spec.LoggingConfiguration.LogDestinationConfigs
		input = rm.newLoggingConfigurationPayload(desired)
		input.LoggingConfiguration = &svcsdk.LoggingConfiguration{}
	} else {
		delete = latest.ko.Spec.LoggingConfiguration.LogDestinationConfigs
		input = rm.newLoggingConfigurationPayload(latest)
	}

	// UpdateLoggingConfiguration allows only single LogDestinationConfig
	// update at a time. So the updates (delete/add) need to be done in a loop.
	for _, c := range delete {
		resf0elem := &svcsdk.LogDestinationConfig{}

		resf0elem.SetLogDestination(c.LogDestination)
		resf0elem.SetLogDestinationType(*c.LogDestinationType)
		resf0elem.SetLogType(*c.LogType)

		for i, config := range input.LoggingConfiguration.LogDestinationConfigs {
			if reflect.DeepEqual(config, resf0elem) {
				// Swap with the last element
				input.LoggingConfiguration.LogDestinationConfigs[i] = input.LoggingConfiguration.LogDestinationConfigs[len(input.LoggingConfiguration.LogDestinationConfigs)-1]
				// Reduce the slice's length by 1
				input.LoggingConfiguration.LogDestinationConfigs = input.LoggingConfiguration.LogDestinationConfigs[:len(input.LoggingConfiguration.LogDestinationConfigs)-1]

				output, err := rm.sdkapi.UpdateLoggingConfigurationWithContext(ctx, input)
				rm.metrics.RecordAPICall("UPDATE", "UpdateLoggingConfiguration", err)
				if err != nil {
					return err
				}
				input.FirewallName = output.FirewallName
				input.LoggingConfiguration = output.LoggingConfiguration
			}
		}
	}

	for _, c := range add {
		resf0elem := &svcsdk.LogDestinationConfig{}

		resf0elem.SetLogDestination(c.LogDestination)
		resf0elem.SetLogDestinationType(*c.LogDestinationType)
		resf0elem.SetLogType(*c.LogType)

		input.LoggingConfiguration.LogDestinationConfigs = append(input.LoggingConfiguration.LogDestinationConfigs, resf0elem)

		output, err := rm.sdkapi.UpdateLoggingConfigurationWithContext(ctx, input)
		rm.metrics.RecordAPICall("UPDATE", "UpdateLoggingConfiguration", err)
		if err != nil {
			return err
		}
		input.FirewallName = output.FirewallName
		input.LoggingConfiguration = output.LoggingConfiguration
	}

	return nil
}

//endregion logging

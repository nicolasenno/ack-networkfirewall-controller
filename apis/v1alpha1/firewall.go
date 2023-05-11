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

// Code generated by ack-generate. DO NOT EDIT.

package v1alpha1

import (
	ackv1alpha1 "github.com/aws-controllers-k8s/runtime/apis/core/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// FirewallSpec defines the desired state of Firewall.
//
// The firewall defines the configuration settings for an Network Firewall firewall.
// These settings include the firewall policy, the subnets in your VPC to use
// for the firewall endpoints, and any tags that are attached to the firewall
// Amazon Web Services resource.
//
// The status of the firewall, for example whether it's ready to filter network
// traffic, is provided in the corresponding FirewallStatus. You can retrieve
// both objects by calling DescribeFirewall.
type FirewallSpec struct {

	// A flag indicating whether it is possible to delete the firewall. A setting
	// of TRUE indicates that the firewall is protected against deletion. Use this
	// setting to protect against accidentally deleting a firewall that is in use.
	// When you create a firewall, the operation initializes this flag to TRUE.
	DeleteProtection *bool `json:"deleteProtection,omitempty"`
	// A description of the firewall.
	Description *string `json:"description,omitempty"`
	// A complex type that contains settings for encryption of your firewall resources.
	EncryptionConfiguration *EncryptionConfiguration `json:"encryptionConfiguration,omitempty"`
	// The descriptive name of the firewall. You can't change the name of a firewall
	// after you create it.
	// +kubebuilder:validation:Required
	FirewallName *string `json:"firewallName"`
	// The Amazon Resource Name (ARN) of the FirewallPolicy that you want to use
	// for the firewall.
	// +kubebuilder:validation:Required
	FirewallPolicyARN *string `json:"firewallPolicyARN"`
	// A setting indicating whether the firewall is protected against a change to
	// the firewall policy association. Use this setting to protect against accidentally
	// modifying the firewall policy for a firewall that is in use. When you create
	// a firewall, the operation initializes this setting to TRUE.
	FirewallPolicyChangeProtection *bool `json:"firewallPolicyChangeProtection,omitempty"`
	// A setting indicating whether the firewall is protected against changes to
	// the subnet associations. Use this setting to protect against accidentally
	// modifying the subnet associations for a firewall that is in use. When you
	// create a firewall, the operation initializes this setting to TRUE.
	SubnetChangeProtection *bool `json:"subnetChangeProtection,omitempty"`
	// The public subnets to use for your Network Firewall firewalls. Each subnet
	// must belong to a different Availability Zone in the VPC. Network Firewall
	// creates a firewall endpoint in each subnet.
	// +kubebuilder:validation:Required
	SubnetMappings []*SubnetMapping `json:"subnetMappings"`
	// The key:value pairs to associate with the resource.
	Tags []*Tag `json:"tags,omitempty"`
	// The unique identifier of the VPC where Network Firewall should create the
	// firewall.
	//
	// You can't change this setting after you create the firewall.
	// +kubebuilder:validation:Required
	VPCID *string `json:"vpcID"`
}

// FirewallStatus defines the observed state of Firewall
type FirewallStatus struct {
	// All CRs managed by ACK have a common `Status.ACKResourceMetadata` member
	// that is used to contain resource sync state, account ownership,
	// constructed ARN for the resource
	// +kubebuilder:validation:Optional
	ACKResourceMetadata *ackv1alpha1.ResourceMetadata `json:"ackResourceMetadata"`
	// All CRS managed by ACK have a common `Status.Conditions` member that
	// contains a collection of `ackv1alpha1.Condition` objects that describe
	// the various terminal states of the CR and its backend AWS service API
	// resource
	// +kubebuilder:validation:Optional
	Conditions []*ackv1alpha1.Condition `json:"conditions"`
	// The configuration settings for the firewall. These settings include the firewall
	// policy and the subnets in your VPC to use for the firewall endpoints.
	// +kubebuilder:validation:Optional
	Firewall *Firewall_SDK `json:"firewall,omitempty"`
	// Detailed information about the current status of a Firewall. You can retrieve
	// this for a firewall by calling DescribeFirewall and providing the firewall
	// name and ARN.
	// +kubebuilder:validation:Optional
	FirewallStatus *FirewallStatus_SDK `json:"firewallStatus,omitempty"`
}

// Firewall is the Schema for the Firewalls API
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type Firewall struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              FirewallSpec   `json:"spec,omitempty"`
	Status            FirewallStatus `json:"status,omitempty"`
}

// FirewallList contains a list of Firewall
// +kubebuilder:object:root=true
type FirewallList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Firewall `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Firewall{}, &FirewallList{})
}

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	paws "github.com/pulumi/pulumi-aws/sdk/v5/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/alb"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/autoscaling"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/cloudwatch"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/ec2"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/ecs"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/iam"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/kms"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/lb"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/route53"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/config"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {

		tags := pulumi.StringMap{
			"Application": pulumi.String("Metrics"),
			"Name":        pulumi.String("Metrics-Infra"),
		}

		grafanaCfg := config.New(ctx, "grafana")
		grafanaPort := grafanaCfg.GetInt("port")

		currentIdentity, err := paws.GetCallerIdentity(ctx, nil, nil)
		if err != nil {
			return err
		}
		currentRegion, err := paws.GetRegion(ctx, nil, nil)

		if err != nil {
			return err
		}

		ec2AssumeRole, err := iam.GetPolicyDocument(ctx, &iam.GetPolicyDocumentArgs{
			PolicyId: aws.String("AssumeRole"),
			Statements: []iam.GetPolicyDocumentStatement{{
				Actions: []string{"sts:AssumeRole"},
				Principals: []iam.GetPolicyDocumentStatementPrincipal{
					{
						Identifiers: []string{"ec2.amazonaws.com"},
						Type:        "Service",
					},
				},
			}},
		})

		if err != nil {
			return err
		}

		asgRolePolicy, err := iam.GetPolicyDocument(ctx, &iam.GetPolicyDocumentArgs{
			PolicyId: aws.String("EcsThings"),
			Statements: []iam.GetPolicyDocumentStatement{{
				Actions: []string{
					"ec2:DescribeTags",
					"ecs:CreateCluster",
					"ecs:DeregisterContainerInstance",
					"ecs:DiscoverPollEndpoint",
					"ecs:Poll",
					"ecs:RegisterContainerInstance",
					"ecs:StartTelemetrySession",
					"ecs:UpdateContainerInstancesState",
					"ecs:Submit*",
					"ecr:GetAuthorizationToken",
					"ecr:BatchCheckLayerAvailability",
					"ecr:GetDownloadUrlForLayer",
					"ecr:BatchGetImage",
					"logs:CreateLogStream",
					"logs:PutLogEvents",
				},
				Resources: []string{"*"},
			}},
		})

		if err != nil {
			return err
		}

		asgIamRole, err := iam.NewRole(ctx, "metrics-asg", &iam.RoleArgs{
			AssumeRolePolicy: pulumi.String(ec2AssumeRole.Json),
			InlinePolicies: iam.RoleInlinePolicyArray{
				iam.RoleInlinePolicyArgs{
					Name:   pulumi.String("ecs-instance-permissions"),
					Policy: pulumi.String(asgRolePolicy.Json),
				},
			},
			Tags: tags,
		})

		if err != nil {
			return err
		}

		asgInstanceProfile, err := iam.NewInstanceProfile(ctx, "metrics-asg", &iam.InstanceProfileArgs{
			Role: asgIamRole.Name,
		})

		if err != nil {
			return err
		}

		execAssumeRolePolicy, err := iam.GetPolicyDocument(ctx, &iam.GetPolicyDocumentArgs{
			PolicyId: aws.String("AssumeRole"),
			Statements: []iam.GetPolicyDocumentStatement{{
				Actions: []string{"sts:AssumeRole"},
				Principals: []iam.GetPolicyDocumentStatementPrincipal{
					{
						Identifiers: []string{"ecs-tasks.amazonaws.com"},
						Type:        "Service",
					},
				},
			}},
		})

		if err != nil {
			return err
		}

		execRolePolicy, err := iam.GetPolicyDocument(ctx, &iam.GetPolicyDocumentArgs{
			PolicyId: aws.String("AssumeRole"),
			Statements: []iam.GetPolicyDocumentStatement{{
				Actions: []string{
					"ecr:GetAuthorizationToken",
					"ecr:BatchCheckLayerAvailability",
					"ecr:GetDownloadUrlForLayer",
					"ecr:BatchGetImage",
					"logs:CreateLogStream",
					"logs:PutLogEvents",
				},
				Resources: []string{"*"},
			}},
		})

		if err != nil {
			return err
		}

		ecsExecRole, err := iam.NewRole(ctx, "metrics-exec", &iam.RoleArgs{
			AssumeRolePolicy: pulumi.String(execAssumeRolePolicy.Json),
			InlinePolicies: iam.RoleInlinePolicyArray{
				iam.RoleInlinePolicyArgs{
					Name:   pulumi.String("exec-role"),
					Policy: pulumi.String(execRolePolicy.Json),
				},
			},
			Tags: tags,
		})

		if err != nil {
			return err
		}

		metricsKmsPolicy, err := iam.GetPolicyDocument(ctx, &iam.GetPolicyDocumentArgs{
			PolicyId: aws.String("EcsKms"),
			Statements: []iam.GetPolicyDocumentStatement{
				{
					Actions: []string{
						"kms:Encrypt*",
						"kms:Decrypt*",
						"kms:ReEncrypt*",
						"kms:GenerateDataKey*",
						"kms:Describe*",
					},
					Principals: []iam.GetPolicyDocumentStatementPrincipal{
						{
							Identifiers: []string{
								"ecs.amazonaws.com",
								"logs.amazonaws.com",
							},
							Type: "Service",
						},
					},
					Resources: []string{"*"},
				},
				{
					Actions: []string{
						"kms:*",
					},
					Principals: []iam.GetPolicyDocumentStatementPrincipal{
						{
							Identifiers: []string{fmt.Sprintf("arn:aws:iam::%v:root", currentIdentity.AccountId)},
							Type:        "AWS",
						},
					},
					Resources: []string{"*"},
				},
			},
		})

		if err != nil {
			return err
		}

		metricsKms, err := kms.NewKey(ctx, "key", &kms.KeyArgs{
			DeletionWindowInDays: pulumi.Int(7),
			Description:          pulumi.String("metrics data"),
			Policy:               pulumi.StringPtr(metricsKmsPolicy.Json),
			Tags:                 tags,
		})

		if err != nil {
			return err
		}

		_, err = kms.NewAlias(ctx, "key", &kms.AliasArgs{
			Name:        pulumi.StringPtr("alias/metrics-cluster"),
			TargetKeyId: metricsKms.Arn,
		})

		if err != nil {
			return err
		}

		logroup, err := cloudwatch.NewLogGroup(ctx, "metrics", &cloudwatch.LogGroupArgs{
			KmsKeyId:        metricsKms.Arn,
			RetentionInDays: pulumi.Int(1),
			Tags:            tags,
		})

		if err != nil {
			return err
		}

		cluster, err := ecs.NewCluster(ctx, "metrics", &ecs.ClusterArgs{
			Configuration: ecs.ClusterConfigurationArgs{
				ExecuteCommandConfiguration: ecs.ClusterConfigurationExecuteCommandConfigurationArgs{
					KmsKeyId: metricsKms.KeyId,
					Logging:  pulumi.String("DEFAULT"),
				},
			},
			Settings: ecs.ClusterSettingArray{
				&ecs.ClusterSettingArgs{
					Name:  pulumi.String("containerInsights"),
					Value: pulumi.String("disabled"),
				},
			},
			Tags: tags,
		})

		if err != nil {
			return err
		}

		vpc, err := ec2.NewVpc(ctx, "metrics", &ec2.VpcArgs{
			CidrBlock: pulumi.StringPtr("10.0.0.0/16"),
			Tags:      tags,
		})

		if err != nil {
			return err
		}

		privsub1, err := ec2.NewSubnet(ctx, "metrics-priv-subnet1", &ec2.SubnetArgs{
			AvailabilityZone: pulumi.StringPtr("us-east-1a"),
			CidrBlock:        pulumi.StringPtr("10.0.0.0/24"),
			VpcId:            vpc.ID(),
			Tags:             tags,
		})

		if err != nil {
			return err
		}

		privsub2, err := ec2.NewSubnet(ctx, "metrics-priv-subnet2", &ec2.SubnetArgs{
			AvailabilityZone: pulumi.StringPtr("us-east-1b"),
			CidrBlock:        pulumi.StringPtr("10.0.1.0/24"),
			VpcId:            vpc.ID(),
			Tags:             tags,
		})

		if err != nil {
			return err
		}

		pubsub1, err := ec2.NewSubnet(ctx, "metrics-pub-subnet1", &ec2.SubnetArgs{
			AvailabilityZone: pulumi.StringPtr("us-east-1b"),
			CidrBlock:        pulumi.StringPtr("10.0.2.0/24"),
			VpcId:            vpc.ID(),
			Tags:             tags,
		})

		if err != nil {
			return err
		}

		pubsub2, err := ec2.NewSubnet(ctx, "metrics-pub-subnet2", &ec2.SubnetArgs{
			AvailabilityZone: pulumi.StringPtr("us-east-1a"),
			CidrBlock:        pulumi.StringPtr("10.0.4.0/24"),
			VpcId:            vpc.ID(),
			Tags:             tags,
		})

		if err != nil {
			return err
		}

		igw, err := ec2.NewInternetGateway(ctx, "metrics", &ec2.InternetGatewayArgs{
			VpcId: vpc.ID(),
			Tags:  tags,
		})

		if err != nil {
			return err
		}

		eipNat, err := ec2.NewEip(ctx, "metrics-nat", &ec2.EipArgs{
			Tags: tags,
		})

		if err != nil {
			return err
		}

		nat, err := ec2.NewNatGateway(ctx, "metrics", &ec2.NatGatewayArgs{
			SubnetId:     pubsub1.ID(),
			AllocationId: eipNat.AllocationId,
			Tags:         tags,
		})

		if err != nil {
			return err
		}

		pubroutetbl, err := ec2.NewRouteTable(ctx, "metrics-pub", &ec2.RouteTableArgs{
			Routes: ec2.RouteTableRouteArray{
				ec2.RouteTableRouteArgs{
					CidrBlock: pulumi.StringPtr("0.0.0.0/0"),
					GatewayId: igw.ID(),
				},
			},
			VpcId: vpc.ID(),
			Tags:  tags,
		})

		if err != nil {
			return err
		}

		privroutetbl, err := ec2.NewRouteTable(ctx, "metrics-priv", &ec2.RouteTableArgs{
			Routes: ec2.RouteTableRouteArray{
				ec2.RouteTableRouteArgs{
					CidrBlock:    pulumi.StringPtr("0.0.0.0/0"),
					NatGatewayId: nat.ID(),
				},
			},
			VpcId: vpc.ID(),
			Tags:  tags,
		})

		if err != nil {
			return err
		}

		albSg, err := ec2.NewSecurityGroup(ctx, "metrics-lb", &ec2.SecurityGroupArgs{
			VpcId:       vpc.ID(),
			Description: pulumi.StringPtr("GrafanaLB"),
			Ingress: ec2.SecurityGroupIngressArray{
				ec2.SecurityGroupIngressArgs{
					FromPort: pulumi.Int(grafanaPort),
					Protocol: pulumi.String("tcp"),
					ToPort:   pulumi.Int(grafanaPort),
					CidrBlocks: pulumi.StringArray{
						pulumi.String("73.131.106.241/32"),
					},
				},
			},
			Tags: tags,
		})

		if err != nil {
			return err
		}

		albPub, err := alb.NewLoadBalancer(ctx, "metrics", &alb.LoadBalancerArgs{
			Internal:         pulumi.BoolPtr(false),
			LoadBalancerType: pulumi.String("application"),
			Subnets:          pulumi.StringArray{pubsub1.ID(), pubsub2.ID()},
			SecurityGroups:   pulumi.StringArray{albSg.ID()},
			Tags:             tags,
		})

		if err != nil {
			return err
		}
		containerDefinition := logroup.Name.ApplyT(func(v string) string {
			definitions := []map[string]interface{}{
				{
					"name":      "grafana",
					"image":     "grafana/grafana:latest",
					"essential": true,
					"portMappings": []map[string]int{
						{
							"containerPort": grafanaPort,
						},
					},
					"environment": []map[string]string{
						{
							"name":  "GF_SERVER_HTTP_PORT",
							"value": fmt.Sprintf("%v", grafanaPort),
						},
					},
					"memory": 2048,
					"logConfiguration": map[string]interface{}{
						"logDriver": "awslogs",
						"options": map[string]string{
							"awslogs-group":         v,
							"awslogs-region":        currentRegion.Name,
							"awslogs-create-group":  "true",
							"awslogs-stream-prefix": "grafana",
						},
					},
				},
			}
			return jsonString(definitions)
		}).(pulumi.StringOutput)

		serviceSg, err := ec2.NewSecurityGroup(ctx, "metrics-service", &ec2.SecurityGroupArgs{
			VpcId:       vpc.ID(),
			Description: pulumi.StringPtr("GrafanaLB"),
			Ingress: ec2.SecurityGroupIngressArray{
				ec2.SecurityGroupIngressArgs{
					FromPort:       pulumi.Int(grafanaPort),
					Protocol:       pulumi.String("tcp"),
					ToPort:         pulumi.Int(grafanaPort),
					SecurityGroups: pulumi.StringArray{albSg.ID()},
				},
			},
			Egress: ec2.SecurityGroupEgressArray{
				ec2.SecurityGroupEgressArgs{
					FromPort:   pulumi.Int(443),
					Protocol:   pulumi.String("tcp"),
					ToPort:     pulumi.Int(443),
					CidrBlocks: pulumi.StringArray{pulumi.String("0.0.0.0/0")},
				},
			},

			Tags: tags,
		})

		if err != nil {
			return err
		}

		userData := cluster.Name.ApplyT(func(v string) string {
			return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("#!/bin/bash\necho \"ECS_CLUSTER=%v\" >> /etc/ecs/ecs.config", v)))
		}).(pulumi.StringOutput)

		lt, err := ec2.NewLaunchTemplate(ctx, "metrics", &ec2.LaunchTemplateArgs{
			NamePrefix:   pulumi.StringPtr("metrics-"),
			ImageId:      pulumi.StringPtr("ami-00eb90638788e810f"),
			InstanceType: pulumi.StringPtr("t3.large"),
			IamInstanceProfile: &ec2.LaunchTemplateIamInstanceProfileArgs{
				Arn: asgInstanceProfile.Arn,
			},
			VpcSecurityGroupIds: pulumi.StringArray{
				serviceSg.ID(),
			},
			UserData: userData,
			Tags:     tags,
		})
		if err != nil {
			return err
		}

		tg, err := lb.NewTargetGroup(ctx, "metrics", &lb.TargetGroupArgs{
			NamePrefix: pulumi.StringPtr("mgraf-"),
			Port:       pulumi.IntPtr(grafanaPort),
			Protocol:   pulumi.StringPtr("HTTP"),
			HealthCheck: lb.TargetGroupHealthCheckArgs{
				Enabled: pulumi.BoolPtr(true),
				Port:    pulumi.StringPtr(fmt.Sprintf("%v", grafanaPort)),
				Path:    pulumi.StringPtr("/"),
				Matcher: pulumi.StringPtr("302"),
			},
			VpcId:      vpc.ID(),
			TargetType: pulumi.StringPtr("ip"),
			Tags:       tags,
		})

		if err != nil {
			return err
		}

		_, err = ec2.NewRouteTableAssociation(ctx, "pubsub1", &ec2.RouteTableAssociationArgs{
			SubnetId:     pubsub1.ID(),
			RouteTableId: pubroutetbl.ID(),
		})
		if err != nil {
			return err
		}

		_, err = ec2.NewRouteTableAssociation(ctx, "pubsub2", &ec2.RouteTableAssociationArgs{
			SubnetId:     pubsub2.ID(),
			RouteTableId: pubroutetbl.ID(),
		})
		if err != nil {
			return err
		}

		_, err = ec2.NewRouteTableAssociation(ctx, "privsub1", &ec2.RouteTableAssociationArgs{
			SubnetId:     privsub1.ID(),
			RouteTableId: privroutetbl.ID(),
		})
		if err != nil {
			return err
		}

		_, err = ec2.NewRouteTableAssociation(ctx, "privsub2", &ec2.RouteTableAssociationArgs{
			SubnetId:     privsub2.ID(),
			RouteTableId: privroutetbl.ID(),
		})
		if err != nil {
			return err
		}

		_, err = autoscaling.NewGroup(ctx, "metrics", &autoscaling.GroupArgs{
			DesiredCapacity: pulumi.IntPtr(2),
			MaxSize:         pulumi.Int(2),
			MinSize:         pulumi.Int(1),
			VpcZoneIdentifiers: pulumi.StringArray{
				privsub2.ID(),
				privsub1.ID(),
			},
			LaunchTemplate: &autoscaling.GroupLaunchTemplateArgs{
				Id:      lt.ID(),
				Version: pulumi.StringPtr("$Latest"),
			},
			Tags: func(t pulumi.StringMap) autoscaling.GroupTagArray {
				x := autoscaling.GroupTagArray{}
				for k, v := range t {
					x = append(x, autoscaling.GroupTagArgs{
						Key:               pulumi.String(k),
						Value:             v,
						PropagateAtLaunch: pulumi.Bool(true),
					})
				}
				return x
			}(tags),
		}, pulumi.DependsOn([]pulumi.Resource{igw, nat}))
		if err != nil {
			return err
		}

		_, err = lb.NewListener(ctx, "metrics", &lb.ListenerArgs{
			LoadBalancerArn: albPub.Arn,
			Port:            pulumi.IntPtr(grafanaPort),
			Protocol:        pulumi.StringPtr("HTTP"),
			DefaultActions: lb.ListenerDefaultActionArray{
				&lb.ListenerDefaultActionArgs{
					Type:           pulumi.String("forward"),
					TargetGroupArn: tg.Arn,
				},
			},
			Tags: tags,
		})
		if err != nil {
			return err
		}

		taskdef, err := ecs.NewTaskDefinition(ctx, "metrics", &ecs.TaskDefinitionArgs{
			ExecutionRoleArn:     ecsExecRole.Arn,
			Cpu:                  pulumi.StringPtr("256"),
			NetworkMode:          pulumi.StringPtr("awsvpc"),
			ContainerDefinitions: containerDefinition,
			Family:               pulumi.String("grafana"),
			Tags:                 tags,
		})

		if err != nil {
			return err
		}

		_, err = ecs.NewService(ctx, "metrics", &ecs.ServiceArgs{
			Cluster:              cluster.Arn,
			DesiredCount:         pulumi.IntPtr(1),
			EnableEcsManagedTags: pulumi.BoolPtr(true),
			NetworkConfiguration: ecs.ServiceNetworkConfigurationArgs{
				SecurityGroups: pulumi.StringArray{
					serviceSg.ID(),
				},
				Subnets: pulumi.StringArray{
					privsub2.ID(), privsub1.ID(),
				},
			},
			LoadBalancers: ecs.ServiceLoadBalancerArray{
				ecs.ServiceLoadBalancerArgs{
					ContainerName:  pulumi.String("grafana"),
					ContainerPort:  pulumi.Int(grafanaPort),
					TargetGroupArn: tg.Arn.ToStringPtrOutput(),
				},
			},
			TaskDefinition: taskdef.Arn,
			Tags:           tags,
		})

		if err != nil {
			return err
		}

		r53, err := route53.NewRecord(ctx, "grafana", &route53.RecordArgs{
			ZoneId: pulumi.String("Z2OYCXY9W3QISD"),
			Name:   pulumi.String("grafana.chscloudsec.com"),
			Type:   pulumi.String("A"),
			Aliases: route53.RecordAliasArray{
				&route53.RecordAliasArgs{
					Name:                 albPub.DnsName,
					EvaluateTargetHealth: pulumi.Bool(true),
					ZoneId:               albPub.ZoneId,
				},
			},
		})

		if err != nil {
			return err
		}

		_, err = ec2.NewSecurityGroupRule(ctx, "alb-sg-keepalive", &ec2.SecurityGroupRuleArgs{
			FromPort:              pulumi.Int(grafanaPort),
			ToPort:                pulumi.Int(grafanaPort),
			SecurityGroupId:       albSg.ID(),
			Protocol:              pulumi.String("tcp"),
			SourceSecurityGroupId: serviceSg.ID(),
			Type:                  pulumi.String("egress"),
		})
		if err != nil {
			return err
		}

		url := r53.Fqdn.ApplyT(func(v string) string {
			return fmt.Sprintf("http://%v:%v", v, grafanaPort)
		}).(pulumi.StringOutput)
		ctx.Export("URL", url)
		return err
	})
}

func jsonString(i interface{}) string {
	xb, _ := json.Marshal(i)
	return string(xb)
}

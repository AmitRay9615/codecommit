import boto3
import time
import re
import sys
import json
import requests
from pprint import pprint


ec2 = boto3.client(
    'ec2',
    aws_access_key_id= 'AKIA4QIWBQQQLN2TC5WC',
    aws_secret_access_key= '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',
    region_name='ap-south-1'
)
inspec = boto3.client(
    'inspector',
    aws_access_key_id='AKIA4QIWBQQQLN2TC5WC',
    aws_secret_access_key='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',
    region_name='ap-south-1'
)

s3 = boto3.resource(
    's3',
    aws_access_key_id='AKIA4QIWBQQQLN2TC5WC',
    aws_secret_access_key='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',
)
#ami_name = ['amzn2-ami-ecs-gpu-hvm-2.0.*','unsilo-ecs-optimized-*','unsilo-focalbase-*','unsilo-es7-*','amazon-eks-node-1.21-*']



RULE_MAP = {
   
    "us-east-1": {
        "CVE": "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-gEjTy7T7",
        "CIS": "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-rExsr2X8",
        "Network Reachability": "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-PmNV0Tcd",
        "Best Practices": "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-R01qwB5Q",
    },
    "ap-south-1": {
        "CVE": "arn:aws:inspector:ap-south-1:162588757376:rulespackage/0-LqnJE9dO",
        "CIS": "arn:aws:inspector:ap-south-1:162588757376:rulespackage/0-PSUlX14m",
        "Network Reachability": "arn:aws:inspector:ap-south-1:162588757376:rulespackage/0-YxKfjFu1",
        "Best Practices": "arn:aws:inspector:ap-south-1:162588757376:rulespackage/0-fs0IZZBj",
    },

}

ami_name = ['httpd-*']
response = ec2.describe_images(Filters=[{'Name':'name', 'Values': ami_name}])
images=response['Images']
pprint(images)
prefix='2022-'
for img in images:
    if img['CreationDate'].startswith(prefix):
        print(img['ImageId']," ----- ",img['Name'],"----------- ",img['CreationDate'])
        
        pprint(ec2.describe_images(Filters=[{'Name':'image-id', 'Values': [img['ImageId']]}]))
       
        #out=ec2.run_instances(ImageId=img['ImageId'],InstanceType='t2.micro',MaxCount=1,MinCount=1,NetworkInterfaces=[{'SubnetId': 'subnet-08af92491d5b60c8c','DeviceIndex': 0,'Groups': ['sg-08073df0a483ccf66']}])
        
        out=ec2.run_instances(ImageId=img['ImageId'],InstanceType='t2.micro',MaxCount=1,MinCount=1)

    

        instanceId= out['Instances'][0]['InstanceId']
        
        ec2.create_tags(Resources=[instanceId], Tags=[{"Key": 'Inspector', "Value": 'true'}])
        
        
        resourcegroup_tags = [{"key": 'Inspector', "value": 'true'}]
        resourcegroup_arn = inspec.create_resource_group(resourceGroupTags=resourcegroup_tags).get("resourceGroupArn")
        # pprint(resourcegroup_arn)


        assessment_target_arn = inspec.create_assessment_target(assessmentTargetName='AWSInspectorTest', resourceGroupArn=resourcegroup_arn).get('assessmentTargetArn')
        # pprint(assessment_target_arn)

        rulepackagearns = [value for rule, value in RULE_MAP.get('ap-south-1').items()]
        # pprint(rulepackagearns)
        
        template_arn=inspec.create_assessment_template(assessmentTargetArn=assessment_target_arn,assessmentTemplateName='AWSassesstemp',durationInSeconds=900,rulesPackageArns=rulepackagearns).get('assessmentTemplateArn')
        # pprint(template_arn)

        
        temp=True
        while True:
            try:
                if temp:
                    assessmentrun_arn=inspec.start_assessment_run(assessmentTemplateArn=template_arn).get('assessmentRunArn')
                    temp=False
                if assessmentrun_arn!='':
                    break
            except Exception:
                pass
        while True:
            
            try:
                report_status = inspec.get_assessment_report(assessmentRunArn=assessmentrun_arn,reportFileFormat='PDF',reportType='FINDING').get('status')
                if report_status == 'COMPLETED':
                    report_url = inspec.get_assessment_report(assessmentRunArn=assessmentrun_arn,reportFileFormat='PDF',reportType='FINDING').get('url')
                    # print(report_url)
                    break


            except Exception:
                pass

        
        res = requests.get(report_url)
        with open(f"{img['Name']}.pdf", 'wb') as f:
           f.write(res.content)

        s3.Bucket('dggg').upload_file(f"{img['Name']}.pdf", "sys.argv[2]/f'{img['Name']}.pdf'")

        inspec.delete_assessment_target(assessmentTargetArn=assessment_target_arn)
        ec2.terminate_instances(InstanceIds=[instanceId])
        print("############################################# output ##########################################")
        print(sys.argv[1])
        








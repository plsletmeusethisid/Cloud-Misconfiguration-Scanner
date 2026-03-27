POLICIES = [
    {
        "name": "Open SSH",
        "severity": "HIGH",
        "rule": '''
            resource.type == "security_group" AND
            EXISTS config.inbound_rules WHERE port == 22 AND is_public == true
        '''
    },
    {
        "name": "Public S3 without encryption",
        "severity": "CRITICAL",
        "rule": '''
            resource.type == "s3_bucket" AND
            config.public == true AND
            config.encryption == false
        '''
    },
    {
        "name": "Internet Exposure",
        "severity": "HIGH",
        "rule": '''
            EXISTS relationships WHERE target_id == "internet"
        '''
    }
]

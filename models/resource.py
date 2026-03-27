def create_resource(resource_id, resource_type, provider="aws", region=None):
    return {
        "id": resource_id,
        "type": resource_type,
        "provider": provider,
        "region": region,
        "config": {},
        "relationships": []
    }

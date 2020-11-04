CREATE USER myuser;
CREATE DATABASE ab3;
GRANT ALL PRIVILEGES ON DATABASE ab3 TO myuser;

CREATE TABLE tenants (
    id VARCHAR(255) NOT NULL,
    company_name VARCHAR(255) NOT NULL,
    tier VARCHAR(10) NOT NULL,
    identity_pool_id VARCHAR(255),
    user_pool_id VARCHAR(255),
    client_id VARCHAR(255),
    system_admin_role VARCHAR(255),
    system_support_role VARCHAR(255),
    trust_role VARCHAR(255),
    system_admin_policy VARCHAR(255),
    system_support_policy VARCHAR(255),
    status VARCHAR(255) DEFAULT 'active'
);

CREATE TABLE users (
    id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    role VARCHAR(255) NOT NULL,
    first_name VARCHAR(255),
    family_name VARCHAR(255),
    email VARCHAR(255)
);

CREATE TABLE products (
    id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    title VARCHAR(255) NOT NULL,
    unit_cost INT NOT NULL
);
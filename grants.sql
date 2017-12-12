/*
  Script  to give grants required fro RAS-Export application
  Should be executed as SYS
*/

ACCEPT APP_SCHEMA CHAR PROMPT 'Please input APPLICATION SCHEMA: '
  
grant select on dba_xs_users to &APP_SCHEMA;
grant select on DBA_XS_ROLES  to &APP_SCHEMA;
grant select on DBA_XS_DYNAMIC_ROLES to &APP_SCHEMA;
grant select on DBA_XS_ROLE_GRANTS to &APP_SCHEMA;
grant select on DBA_XS_SECURITY_CLASSES to &APP_SCHEMA;
grant select on DBA_XS_SECURITY_CLASS_DEP to &APP_SCHEMA;
grant select on dba_xs_privileges to &APP_SCHEMA;
grant select on DBA_XS_IMPLIED_PRIVILEGES to &APP_SCHEMA;
grant select on DBA_XS_POLICIES to &APP_SCHEMA;
grant select on dba_xs_acls to &APP_SCHEMA;
grant select on dba_xs_aces to &APP_SCHEMA;
grant select on DBA_XS_REALM_CONSTRAINTS to &APP_SCHEMA;
grant select on DBA_XS_POLICIES to &APP_SCHEMA;
grant select on dba_xs_column_constraints to &APP_SCHEMA;
grant select on DBA_XS_APPLIED_POLICIES to &APP_SCHEMA;
grant select on dba_xs_acl_parameters to &APP_SCHEMA;
grant select on xs$validation_table to &APP_SCHEMA;
grant select on dba_xs_ns_templates to &APP_SCHEMA;
grant select on dba_xs_ns_template_attributes to &APP_SCHEMA;
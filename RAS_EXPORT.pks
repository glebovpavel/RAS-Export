create or replace PACKAGE      "RAS_EXPORT" AS 
  
  /* first grant select on objects listed below to apex-schema */ 
  
  -- grant select on dba_xs_users to HR;
  -- grant select on DBA_XS_ROLES  to hr
  -- grant select on DBA_XS_DYNAMIC_ROLES to hr
  -- grant select on DBA_XS_ROLE_GRANTS to hr
  -- grant select on sys.DBA_XS_SECURITY_CLASSES to hr
  -- grant select on sys.DBA_XS_SECURITY_CLASS_DEP to hr
  -- grant select on dba_xs_privileges to hr
  -- grant select on DBA_XS_IMPLIED_PRIVILEGES to hr
  -- grant select on sys.DBA_XS_POLICIES to hr
  -- grant select on dba_xs_acls to hr
  -- grant select on dba_xs_aces to hr
  -- grant select on DBA_XS_REALM_CONSTRAINTS to hr
  -- grant select on DBA_XS_POLICIES to hr
  -- grant select on dba_xs_column_constraints to hr
  -- grant select on DBA_XS_APPLIED_POLICIES to hr
  -- grant select on dba_xs_acl_parameters to hr
  -- grant select on xs$validation_table to hr
  
  function export_all(p_delete_flag in varchar2)
  return clob;

  function export_xs_users(p_list   in clob,
                           p_delete in varchar2 default 'N') 
  return clob;
  
  function export_xs_regular_roles(p_list   in clob,
                                   p_delete in varchar2 default 'N')
  return clob;
  
  function export_xs_dynamic_roles(p_list   in clob,
                                   p_delete in varchar2 default 'N')
  return clob;

  function export_xs_grants(p_list in clob default '')
  return clob;

  function export_security_classes(p_list   in clob,
                                   p_delete in varchar2 default 'N')
  return clob;
  
  function export_security_classes_dep(p_list in clob)
  return clob;

  function is_in_list(p_list in clob,p_value in varchar2)
  return varchar2;
  
  procedure download_file(p_delete_flag in varchar2);
  
END RAS_EXPORT;
create or replace PACKAGE BODY RAS_EXPORT AS
 
 EOL constant varchar2(1) default chr(10);
 TIMESTAMP_FORMAT  varchar2(22) default 'DD.MM.RR HH24:MI:SSXFF';
 LIST_DELIMETER    varchar2(1) default ':';  
 
 cursor xs_users(p_list in clob) is
 select name,
        schema,
        decode(status,'ACTIVE',  'XS_PRINCIPAL.ACTIVE',
                      'INACTIVE','XS_PRINCIPAL.INACTIVE',
                      'UNLOCKED','XS_PRINCIPAL.UNLOCKED', -- deprecated in 12.1.0.2
                      'EXPIRED', 'XS_PRINCIPAL.EXPIRED',  -- deprecated in 12.1.0.2
                      'LOCKED',  'XS_PRINCIPAL.LOCKED'    -- deprecated in 12.1.0.2
                      ) as status,
        start_date,
        end_date,
        guid,
        external_source,
        description
  from dba_xs_users
  where is_in_list(p_list,name) = 'Y';
  
  cursor xs_regular_roles(p_list in clob) is
  select name,
       default_enabled,
       start_date,
       end_date,
       guid,
       external_source,
       description
  from DBA_XS_ROLES
  where is_in_list(p_list,name) = 'Y';
        
  cursor xs_dynamic_roles(p_list in clob) is
  select name,
       duration,
       decode(scope,'SESSION',SYS.XS_PRINCIPAL.SESSION_SCOPE,
                    'REQUEST',SYS.XS_PRINCIPAL.REQUEST_SCOPE) as scope,
       description
  from DBA_XS_DYNAMIC_ROLES
  where is_in_list(p_list,name) = 'Y';
        
  cursor xs_roles_grants_app(p_list in clob) is
  select grantee,
       GRANTED_ROLE as role,
       start_date,
       end_date,
       GRANTED_ROLE_TYPE
  from DBA_XS_ROLE_GRANTS 
  where GRANTED_ROLE_TYPE = 'APPLICATION'
    and is_in_list(p_list,grantee) = 'Y';
        
  cursor xs_roles_grants_db(p_list in clob) is
  select grantee,
       GRANTED_ROLE as role,
       start_date,
       end_date,
       GRANTED_ROLE_TYPE
  from DBA_XS_ROLE_GRANTS 
  where GRANTED_ROLE_TYPE = 'DATABASE'
    and is_in_list(p_list,grantee) = 'Y';

  cursor xs_security_classes(p_list in clob) is    
  select name,
         owner,
         description 
  from DBA_XS_SECURITY_CLASSES    
  where is_in_list(p_list,owner||'.'||name) = 'Y';
  
  cursor xs_priveleges(p_list in clob) is
  select name,
         description,
         security_class,
         security_class_owner 
   from dba_xs_privileges
   where is_in_list(p_list,security_class_owner||'.'||security_class||'.'||name) = 'Y';
   
   cursor xs_implied_privileges(p_list in clob) is
   select implied_privilege,
          privilege,
          security_class,
          security_class_owner
   from dba_xs_implied_privileges
   where is_in_list(p_list,security_class_owner||'.'||security_class||'.'||privilege) = 'Y';
   
   cursor xs_acls(p_list in clob) is
   select name,
          owner,
          description,
          security_class,
          security_class_owner,
          parent_acl,
          parent_acl_owner,
          case 
            when instr(inheritance_type,'EXT') > 0  then 'SYS.XS_ACL.EXTENDED'
            when instr(inheritance_type,'CON') > 0  then 'SYS.XS_ACL.CONSTRAINED'
            else ''
         end  inheritance_type
   from dba_xs_acls
   where is_in_list(p_list,owner||'.'||name) = 'Y';   
   
   cursor xs_aces(p_acl_owner in varchar2,p_acl in varchar2) is
   select acl,
          owner,
          security_class,
          security_class_owner,
          principal,
          case 
             when principal_type like 'APPLICATION' then 'SYS.XS_ACL.PTYPE_XS'
             when principal_type like 'DATABASE' then 'SYS.XS_ACL.PTYPE_DB' 
             when instr(principal_type,'DN') > 0 then 'SYS.XS_ACL.PTYPE_DN' 
             when instr(principal_type,'EXT') > 0 then 'SYS.XS_ACL.PTYPE_EXTERNAL' 
             else 'SYS.XS_ACL.PTYPE_XS'
           end principal_type,
          inverted_principal,       
          listagg('''"'||privilege||'"''',',') within group (order by ace_order) priv_list
    from dba_xs_aces
    where owner = p_acl_owner
      and acl = p_acl
    group by acl,
           owner,
           security_class,
           security_class_owner,
           principal,
                     case 
             when principal_type like 'APPLICATION' then 'SYS.XS_ACL.PTYPE_XS'
             when principal_type like 'DATABASE' then 'SYS.XS_ACL.PTYPE_DB' 
             when instr(principal_type,'DN') > 0 then 'SYS.XS_ACL.PTYPE_DN' 
             when instr(principal_type,'EXT') > 0 then 'SYS.XS_ACL.PTYPE_EXTERNAL' 
             else 'SYS.XS_ACL.PTYPE_XS'
           end,
           inverted_principal;
           
    cursor xs_policies(p_list in clob) is
    select name,
           owner,
           description 
    from dba_xs_policies
    where is_in_list(p_list,owner||'.'||name) = 'Y';   
    
    cursor xs_realm_constraints(p_policy_owner in varchar2,
                                p_policy in varchar2) 
    is
    select realm_type,
           case 
             when static = 'DYNAMIC' then 'FALSE'
             else 'TRUE'
           end is_static,
           realm,
           realm_description,       
           parent_object,
           parent_schema,
           listagg(''''||acl_owner||'.'||acl||'''',',') within group (order by acl) acl_list
    from dba_xs_realm_constraints
    where policy = p_policy
      and policy_owner = p_policy_owner
    group by realm_type,
           case 
             when static = 'DYNAMIC' then 'FALSE'
             else 'TRUE'
           end,
           realm,
           realm_description,       
           parent_object,
           parent_schema,
           realm_order
    order by realm_order;
    
    cursor xs_column_constraints(p_policy_owner in varchar2,
                                 p_policy in varchar2) is
    select privilege,
           listagg('''"'||column_name||'"''',',') within group (order by column_name) cols
    from  dba_xs_column_constraints
    where policy = p_policy
      and owner = p_policy_owner
    group by privilege;
    
    cursor xs_applied_policies(p_policy_owner in varchar2,
                               p_policy in varchar2) is
    select schema,
       object,
       owner_bypass,
       policy,
       policy_owner,
       row_acl,
       status,
       decode(statmnt,'SEL','SELECT',
                      'UPD','UPDATE',
                      'DEL','DELETE',
                      'INS','INSERT',
                      'IDX','INDEX') as statement_types
  from (
    select * from (
      select schema,
             object,
             owner_bypass,
             policy,
             policy_owner,
             row_acl,
             sel,
             status,
             upd,
             del,
             idx,
             ins 
      from dba_xs_applied_policies
      )
     unpivot (enabled for statmnt in (SEL,UPD,INS,DEL,IDX)
     )
  ) where enabled = 'YES' 
  and policy = p_policy
      and policy_owner = p_policy_owner;
  
 cursor xs_applied_policies_del(p_policy_owner in varchar2,
                                p_policy in varchar2) is    
 select schema,
        object,
        policy,
        policy_owner,
        decode(status,'ENABLED','ENABLE','DISABLE') as status
 from dba_xs_applied_policies    
 where policy = p_policy
   and policy_owner = p_policy_owner;
   
 cursor xs_acl_parameters(p_acl_list in clob)
 is                         
 select acl,
        acl_owner,
        datatype,
        parameter,
        policy,
        policy_owner,
        realm,
        realm_order,
        value
 from dba_xs_acl_parameters
 where is_in_list(p_acl_list,acl_owner||'.'||acl) = 'Y';     
 -------------------------------------------------------------------------------
 
 function num(p_value in number)
 return varchar2
 is
 begin
   if p_value is null then
     return 'NULL';
   else  
     return  to_char(p_value);
   end if;  
 end num;

 -------------------------------------------------------------------------------
 
 function str(p_value in varchar2)
 return varchar2
 is
 begin
   if p_value is null then
     return 'NULL';
   else  
     return  ''''||replace(p_value,'''','''''')||'''';
   end if;  
 end str;
 -------------------------------------------------------------------------------
 
 function time_stmp(p_timestamp in timestamp)
 return varchar2
 is
 begin
   if p_timestamp is null then
     return 'NULL';
   else  
     return 'to_timestamp('''||to_char(p_timestamp,TIMESTAMP_FORMAT)||''','''||TIMESTAMP_FORMAT||''')';
   end if;  
 end time_stmp;
 -------------------------------------------------------------------------------
 
 function raw_(p_raw in raw)
 return varchar2
 is
 begin
   if p_raw is null then
     return 'NULL';
   else
     return UTL_RAW.CAST_TO_VARCHAR2(p_raw);
   end if;
 end raw_;
 -------------------------------------------------------------------------------
 
 function yes_no_to_boolean(p_str in varchar2)
 return varchar2
 is
 begin
   return case when p_str = '''YES''' then 'TRUE' else 'FALSE' end;
 end yes_no_to_boolean;
 -------------------------------------------------------------------------------
 
 function make_block(p_statement in clob,
                     p_comment   in varchar2 default null,
                     p_delete    in boolean default false)
 return clob
 is
   v_str clob;
 begin
   if length(p_statement) = 0 then
     return p_statement;
   end if; 
   
   if p_delete then
     v_str := v_str||'DECLARE
       xs_entity_not_exists EXCEPTION;
       policy_not_exists EXCEPTION;
       PRAGMA EXCEPTION_INIT(policy_not_exists,-28102);
       PRAGMA EXCEPTION_INIT(xs_entity_not_exists, -46215);'||EOL;
   end if;
   v_str := v_str|| 'BEGIN'||EOL||p_statement||EOL||'commit;'||EOL;
   if  p_comment is not null then 
       v_str := v_str||'DBMS_OUTPUT.PUT_LINE('''||p_comment||''');'||EOL; 
   end if;
   if p_delete then
      v_str := v_str||' EXCEPTION WHEN xs_entity_not_exists or policy_not_exists THEN NULL;';
   end if;
   v_str := v_str||'END;'||EOL||'/'||EOL;
   
   return v_str;
 end make_block;
 -------------------------------------------------------------------------------
 
 function is_in_list(p_list in clob,p_value in varchar2)
 return varchar2
 is
 begin
   if instr(LIST_DELIMETER||p_list||LIST_DELIMETER,LIST_DELIMETER||p_value||LIST_DELIMETER) > 0 then 
     return 'Y';
   else
     return 'N';
   end if;
 end is_in_list;
 -------------------------------------------------------------------------------
 
 FUNCTION export_xs_users(p_list   in clob,
                          p_delete in varchar2 default 'N')
 return clob
 is
   v_str    clob;   
 begin   
   for i in xs_users(p_list) loop
     if p_delete = 'Y' then
       v_str := v_str||make_block('SYS.XS_PRINCIPAL.DELETE_PRINCIPAL(
          principal     => '''||i.name||''',
          delete_option => XS_ADMIN_UTIL.CASCADE_OPTION);',
          'Drop User '||i.name,
          p_delete => TRUE
          );
     
     else
       v_str := v_str||make_block('SYS.XS_PRINCIPAL.CREATE_USER( 
          name            => '||str(i.name)||',
          schema          => '||str(i.schema)||',
          status          => '||i.status||',
          start_date      => '||time_stmp(i.start_date)||',
          end_date        => '||time_stmp(i.end_date)||',
          guid            => '||raw_(i.guid)||',
          external_source => '||str(i.external_source)||',
          description     => '||str(i.description)||'); ',
          'Create User '||i.name);
      end if;     
   end loop;
   
   return v_str;
 end export_xs_users;
 -------------------------------------------------------------------------------
 
 function export_xs_regular_roles(p_list   in clob,
                                  p_delete in varchar2 default 'N')
 return clob
 is
   v_str clob;
 begin
   for i in xs_regular_roles(p_list) loop
     if p_delete = 'Y' then
       v_str := v_str||make_block('SYS.XS_PRINCIPAL.DELETE_PRINCIPAL (
          principal     => '||str(i.name)||',
          delete_option => XS_ADMIN_UTIL.CASCADE_OPTION);',
          'Delete regular Role '||i.name,
          p_delete => TRUE);
     else      
       v_str := v_str||make_block('SYS.XS_PRINCIPAL.CREATE_ROLE( 
          name            => '||str(i.name)||',
          enabled         => '||yes_no_to_boolean(i.default_enabled)||',
          start_date      => '||time_stmp(i.start_date)||',
          end_date        => '||time_stmp(i.end_date)||',
          guid            => '||raw_(i.guid)||',
          external_source => '||str(i.external_source)||',
          description     => '||str(i.description)||'); ',
          'Create regular Role '||i.name);
     end if;   
   end loop;
   
   return v_str;
 end export_xs_regular_roles;
 -------------------------------------------------------------------------------
 
 function export_xs_grants(p_list in clob)
 return clob
 is
   v_str clob;
   v_first boolean default true;
 begin
   for i in xs_roles_grants_app(p_list) loop
       v_str := v_str||make_block('SYS.XS_PRINCIPAL.GRANT_ROLES (
          grantee       => '||str(i.grantee)||',
          role          => '||str(i.role)||',
          start_date    => '||time_stmp(i.start_date)||',
          end_date      => '||time_stmp(i.end_date)||');',
          'Grant '||i.role||' to '||i.grantee);
   end loop;
   for i in xs_roles_grants_db(p_list) loop
       if v_first then 
         v_str := v_str||'SET ECHO ON'||EOL||EOL;
       end if;
       v_first := false;       
       v_str := v_str||'GRANT '||i.role||' to '||i.grantee||';'||EOL||EOL;
   end loop;
   if not v_first then 
     v_str := v_str||'SET ECHO OFF'||EOL||EOL;
   end if;  
   
   return v_str;
 end export_xs_grants; 
 -------------------------------------------------------------------------------
 
 function export_xs_dynamic_roles(p_list   in clob,
                                  p_delete in varchar2 default 'N')
 return clob
 is
   v_str clob;
 begin
 for i in xs_dynamic_roles(p_list) loop
     if p_delete = 'Y' then
       v_str := v_str||make_block('SYS.XS_PRINCIPAL.DELETE_PRINCIPAL (
          principal     => '||str(i.name)||',
          delete_option => XS_ADMIN_UTIL.CASCADE_OPTION);',
          'Delete dynamic Role '||i.name,
          p_delete => TRUE);
     else
       v_str := v_str||make_block('SYS.XS_PRINCIPAL.CREATE_DYNAMIC_ROLE( 
          name            => '||str(i.name)||',
          duration        => '||num(i.duration)||', 
          scope           => '||i.scope||', 
          description     => '||str(i.description)||'); ',
          'Create dynamic Role '||i.name);
       v_str := v_str||export_xs_grants(i.name);   
     end if;  
   end loop;

   return v_str;
 end export_xs_dynamic_roles;
 -------------------------------------------------------------------------------
 
 function export_security_classes(p_list   in clob,
                                  p_delete in varchar2 default 'N')
 return clob
 is
   v_str clob;
 begin
 for i in xs_security_classes(p_list) loop
     if p_delete = 'Y' then
       v_str := v_str||make_block('SYS.XS_SECURITY_CLASS.DELETE_SECURITY_CLASS (
          sec_class     => '||str(i.owner||'.'||i.name)||',
          delete_option => SYS.XS_ADMIN_UTIL.CASCADE_OPTION);',
          'Delete Security Class '||i.owner||'.'||i.name,
          p_delete => TRUE);
     else
       v_str := v_str||make_block('XS_SECURITY_CLASS.CREATE_SECURITY_CLASS( 
          name            => '||str(i.owner||'.'||i.name)||',
          priv_list       =>  XS$PRIVILEGE_LIST(),
          description     => '||str(i.description)||'); ',
          'Create Security Class '||i.owner||'.'||i.name);
     end if;  
   end loop;

   return v_str;
 end export_security_classes; 
 -------------------------------------------------------------------------------
 
 function export_security_classes_dep(p_list in clob)
 return clob
 is
   v_str clob;
 begin
 for i in xs_security_classes(p_list) loop
       for a in (select parent,
                        parent_owner
                 from sys.DBA_XS_SECURITY_CLASS_DEP
                 where owner = i.owner
                  and security_class = i.name
                )
        loop        
       v_str := v_str||make_block('XS_SECURITY_CLASS.ADD_PARENTS( 
          sec_class  => '||str(i.owner||'.'||i.name)||',
          parent     => '||str(a.parent_owner||'.'||a.parent)||'); ',
          'Add parent Security Class '||a.parent_owner||'.'||a.parent||' to '||i.owner||'.'||i.name);
        end loop; 
   end loop;

   return v_str;
 end export_security_classes_dep; 
 -------------------------------------------------------------------------------
 
 --!! check if implied_priveleges deletes automatically
 function export_implied_priveleges(p_list in clob,
                            p_delete in varchar2 default 'N')
 return clob
 is
   v_str clob;
 begin
   for i in xs_implied_privileges(p_list) loop
     if p_delete = 'Y' then
       v_str := v_str||make_block('SYS.XS_SECURITY_CLASS.REMOVE_IMPLIED_PRIVILEGES (
          sec_class     => '||str(i.security_class_owner||'.'||i.security_class)||',
          priv          => '||str(i.privilege)||',
          implied_priv  => '||str(i.implied_privilege)||');',
          'Remove implified Privilege '||i.implied_privilege||' from '||i.security_class_owner||'.'||i.security_class||i.privilege,
          p_delete => TRUE);     
     else
       v_str := v_str||make_block('SYS.XS_SECURITY_CLASS.ADD_IMPLIED_PRIVILEGES( 
          sec_class     => '||str(i.security_class_owner||'.'||i.security_class)||',
          priv          => '||str(i.privilege)||',
          implied_priv  => '||str(i.implied_privilege)||');',
          'Add implified Privilege '||i.implied_privilege||' to '||i.security_class_owner||'.'||i.security_class||i.privilege);     
     end if;  
   end loop;

   return v_str;
 end export_implied_priveleges; 
 -------------------------------------------------------------------------------
 
 function has_only_one_privelege(p_security_class_owner in dba_xs_privileges.security_class_owner%TYPE,
                                 p_security_class       in dba_xs_privileges.security_class%TYPE)
 return boolean
 is
   v_tmp number;
 begin
    select count(*)
    into v_tmp
    from dba_xs_privileges
    where security_class = p_security_class
     and security_class_owner = p_security_class_owner;
   
   return nvl(v_tmp,0) > 0;
 end has_only_one_privelege;
 -------------------------------------------------------------------------------
 
 function export_priveleges(p_list in clob,
                            p_delete in varchar2 default 'N')
 return clob
 is
   v_str                    clob;
   v_has_only_one_privelege boolean;
 begin
   for i in xs_priveleges(p_list) loop
     if p_delete = 'Y' then
       v_str := v_str||export_implied_priveleges(p_list => p_list,
                                                 p_delete => 'Y');          
       
       v_has_only_one_privelege := has_only_one_privelege(p_security_class_owner => i.security_class_owner,
                                                          p_security_class       => i.security_class);  
       if v_has_only_one_privelege then 
         -- recreate security class without any privelege
         v_str := v_str||export_security_classes(i.security_class_owner||'.'||i.security_class,
                                                 p_delete => 'Y');
         v_str := v_str||export_security_classes(i.security_class_owner||'.'||i.security_class);                                        
       else
         v_str := v_str||make_block('SYS.XS_SECURITY_CLASS.REMOVE_PRIVILEGES (
            sec_class     => '||str(i.security_class_owner||'.'||i.security_class)||',
            priv          => '||str(i.name)||');',
            'Remove Privilege '||i.name||' from Security Class '||i.security_class_owner||'.'||i.security_class,
            p_delete => TRUE);
       end if;     
     else
       v_str := v_str||make_block('SYS.XS_SECURITY_CLASS.ADD_PRIVILEGES( 
          sec_class     => '||str(i.security_class_owner||'.'||i.security_class)||',
          priv          => '||str(i.name)||',
          description   => '||str(i.description)||');',
          'Add Privilege '||i.name||' to Security Class '||i.security_class_owner||'.'||i.security_class);    
       v_str := v_str||export_implied_priveleges(p_list => p_list);
     end if;  
   end loop;

   return v_str;
 end export_priveleges; 
 -------------------------------------------------------------------------------
 
 function export_acl_paramters(p_acl_list in clob)
 return clob
 is
   v_str   clob;   
 begin
   for i in xs_acl_parameters(p_acl_list => p_acl_list) 
   loop  
       v_str := v_str||make_block(' 
              SYS.XS_ACL.ADD_ACL_PARAMETER    (
                      acl       => '||str(i.acl_owner||'.'||i.acl)||',
                      policy    => '||str(i.policy_owner||'.'||i.policy)||',
                      parameter => '||str(i.parameter)||',
                      value     => '||case when i.datatype = 'NUMBER ' then 'TO_NUMBER' else null end||'('||str(i.value)||'));',
                      'Add ACL Parameter '||i.parameter||' to ACL '||i.acl_owner||'.'||i.acl);
   end loop;

   return  v_str;
 end export_acl_paramters; 
 -------------------------------------------------------------------------------
 
 function get_ace_list(p_acl_owner in varchar2,
                       p_acl       in varchar2)
 return clob
 is
   v_str   clob;
   v_first boolean default true;
 begin
   for i in xs_aces(p_acl_owner => p_acl_owner,
                    p_acl => p_acl) 
   loop
       if not v_first then
         v_str := v_str||','||EOL;
       end if;
       
       v_str := v_str||'
            XS$ACE_TYPE(
                    privilege_list => XS$NAME_LIST('||i.priv_list||'),
                    inverted       => '||yes_no_to_boolean(i.inverted_principal)||',
                    principal_name => '||str(i.principal)||',
                    principal_type => '||i.principal_type||')';
       
       v_first := false;                    
   end loop;

   return 'XS$ACE_LIST('||v_str||')';
 end get_ace_list;  
 -------------------------------------------------------------------------------

 function export_acls(p_list in clob,
                      p_delete in varchar2 default 'N')
 return clob
 is
   v_str clob;
 begin
   for i in xs_acls(p_list) loop
     if p_delete = 'Y' then
       v_str := v_str||make_block('SYS.XS_ACL.DELETE_ACL (
          acl           => '||str(i.owner||'.'||i.name)||',
          delete_option =>  XS_ADMIN_UTIL.CASCADE_OPTION);',
          'Delete ACL '||i.owner||'.'||i.name,
          p_delete => TRUE);
     else       
       v_str := v_str||make_block('SYS.XS_ACL.CREATE_ACL( 
          name          => '||str(i.owner||'.'||i.name)||',
          ace_list      => '||get_ace_list(p_acl_owner => i.owner,
                                           p_acl       => i.name)||',
          sec_class     => '||str(i.security_class_owner||'.'||i.security_class)||',
          description   => '||str(i.description)||');',
          'Create ACL '||i.owner||'.'||i.name);    
     end if;  
   end loop;
   
   if p_delete = 'N' then
      v_str := v_str||export_acl_paramters(p_acl_list => p_list);
   end if;
   
   return v_str;
 end export_acls; 
-------------------------------------------------------------------------------

 function export_acls_inheritance(p_list in clob)
 return clob
 is
   v_str clob;
 begin
   for i in xs_acls(p_list) loop
     if i.parent_acl is not null then
       v_str := v_str||make_block('SYS.XS_ACL.SET_PARENT_ACL( 
          acl              => '||str(i.owner||'.'||i.name)||',
          parent           => '||str(i.parent_acl_owner||'.'||i.parent_acl)||',
          inheritance_type => '||str(i.inheritance_type)||');',
          'Set parent ACL '||i.parent_acl_owner||'.'||i.parent_acl||' for ACL '||i.owner||'.'||i.name);    
      end if;    
   end loop;

   return v_str;
 end export_acls_inheritance; 
 -------------------------------------------------------------------------------
 
 function get_realm_constraints_list(p_policy_owner in varchar2,
                                     p_policy       in varchar2)
 return clob
 is
   v_str   clob;
   v_first boolean default true;   
 begin
   for i in xs_realm_constraints(p_policy_owner => p_policy_owner,
                                 p_policy       => p_policy) 
   loop  
       if not v_first then
         v_str := v_str||','||EOL;
       end if;
       
       if i.realm_type = 'REGULAR' then
         v_str := v_str||'
              XS$REALM_CONSTRAINT_TYPE(
                      realm     =>     q''['||i.realm||']'',
                      acl_list  => XS$NAME_LIST('||i.acl_list||'),
                      is_static => '||i.is_static||')';
       end if;
       
       v_first := false;                    
   end loop;

   return 'XS$REALM_CONSTRAINT_LIST('||v_str||')';
 end get_realm_constraints_list; 
 -------------------------------------------------------------------------------
 
 function get_column_constraints_list(p_policy_owner in varchar2,
                                      p_policy       in varchar2)
 return clob
 is
   v_str   clob;
   v_first boolean default true;   
 begin
   for i in xs_column_constraints(p_policy_owner => p_policy_owner,
                                  p_policy       => p_policy) 
   loop  
       if not v_first then
         v_str := v_str||','||EOL;
       end if;
       
       v_str := v_str||'
              XS$COLUMN_CONSTRAINT_TYPE(
                      column_list       => XS$LIST('||i.cols||'),
                      privilege         => '||str(i.privilege)||')';
       
       v_first := false;                    
   end loop;

   return 'XS$COLUMN_CONSTRAINT_LIST('||v_str||')';
 end get_column_constraints_list; 
 -------------------------------------------------------------------------------
 
 function export_applied_policies(p_policy_owner in varchar2,
                                  p_policy       in varchar2)
 return clob
 is
   v_str   clob;   
 begin
   for i in xs_applied_policies(p_policy_owner => p_policy_owner,
                                p_policy       => p_policy) 
   loop  
       v_str := v_str||make_block(' 
              SYS.XS_DATA_SECURITY.APPLY_OBJECT_POLICY(
                      policy       => '||str(i.policy_owner||'.'||i.policy)||',
                      schema       => '||str(i.schema)||',
                      object       => '||str(i.object)||',
                      row_acl      => '||yes_no_to_boolean(i.row_acl)||',
                      owner_bypass => '||yes_no_to_boolean(i.owner_bypass)||',
                      statement_types    => '||str(i.statement_types)||');',
                      'Apply Policy '||i.policy_owner||'.'||i.policy||' to '||i.schema||'.'||i.object);
   end loop;

   return  v_str;
 end export_applied_policies; 
 -------------------------------------------------------------------------------
 
 function export_applied_policies_del(p_policy_owner in varchar2,
                                      p_policy       in varchar2)
 return clob
 is
   v_str   clob;   
 begin
   for i in xs_applied_policies_del(p_policy_owner => p_policy_owner,
                                    p_policy       => p_policy) 
   loop  
       v_str := v_str||make_block('SYS.XS_DATA_SECURITY.REMOVE_OBJECT_POLICY(
                      policy       => '||str(i.policy_owner||'.'||i.policy)||',
                      schema       => '||str(i.schema)||',
                      object       => '||str(i.object)||');',
                      'Remove Policy '||i.policy_owner||'.'||i.policy||' from '||i.schema||'.'||i.object,
                      p_delete => TRUE);
   end loop;

   return  v_str;
 end export_applied_policies_del; 
 -------------------------------------------------------------------------------
 
 function enable_disable_object_policy(p_policy_owner in varchar2,
                                       p_policy       in varchar2)
 return clob
 is
   v_str           clob; 
 begin
   for i in xs_applied_policies_del(p_policy_owner => p_policy_owner,
                                    p_policy       => p_policy) 
   loop  
       v_str := v_str||make_block('SYS.XS_DATA_SECURITY.'||i.status||'_OBJECT_POLICY(
                         policy       => '||str(i.policy_owner||'.'||i.policy)||',
                         schema       => '||str(i.schema)||',
                         object       => '||str(i.object)||');',
                         initcap(i.status)||' Object Policy from/to '||i.schema||'.'||i.object);
   end loop;

   return  v_str;
 end enable_disable_object_policy; 
 ------------------------------------------------------------------------------- 
 
 function export_policies(p_list in clob,
                          p_delete in varchar2 default 'N')
 return clob
 is
   v_str clob;
 begin
   for i in xs_policies(p_list) loop
     if p_delete = 'Y' then
       v_str := v_str||export_applied_policies_del(p_policy_owner => i.owner,
                                                   p_policy       => i.name);
       v_str := v_str||make_block('SYS.XS_DATA_SECURITY.DELETE_POLICY (
          policy        => '||str(i.owner||'.'||i.name)||',
          delete_option =>  SYS.XS_ADMIN_UTIL.CASCADE_OPTION);',
          'Delete Policy '||i.owner||'.'||i.name,
          p_delete => TRUE);
     else       
       v_str := v_str||make_block('SYS.XS_DATA_SECURITY.CREATE_POLICY( 
          name                   => '||str(i.owner||'.'||i.name)||',
          realm_constraint_list  => '||get_realm_constraints_list(p_policy_owner => i.owner,
                                                                  p_policy       => i.name)||',  
          column_constraint_list => '||get_column_constraints_list(p_policy_owner => i.owner,
                                                                   p_policy       => i.name)||',  
          description   => '||str(i.description)||');',
          'Create Policy '||i.owner||'.'||i.name);    
          
          v_str := v_str||export_applied_policies(p_policy_owner => i.owner,
                                               p_policy       => i.name);
                                               
          v_str := v_str||enable_disable_object_policy(p_policy_owner => i.owner,
                                                       p_policy       => i.name);                                     
     end if;  
   end loop;

   return v_str;
 end export_policies; 
 -------------------------------------------------------------------------------
 
 function export_all(p_delete_flag in varchar2)
 return clob
 is
   v_rrole_list        clob;
   v_drole_list        clob;
   v_user_list         clob;
   v_sclass_list       clob;
   v_priveleges_list   clob;
   v_acls_list         clob;
   v_statement         clob; 
   v_policies          clob;
   
 begin
    select listagg(c002,':') within group (order by c002) as objects
    into v_rrole_list
    from apex_collections
    where COLLECTION_NAME = 'SELECTED_OBJECTS'
      and c001 = 'RROLE';

    select listagg(c002,':') within group (order by c002) as objects
    into v_drole_list
    from apex_collections
    where COLLECTION_NAME = 'SELECTED_OBJECTS'
      and c001 = 'DROLE';

    select listagg(c002,':') within group (order by c002) as objects
    into v_user_list
    from apex_collections
    where COLLECTION_NAME = 'SELECTED_OBJECTS'
      and c001 = 'USER';
      
    select listagg(c002,':') within group (order by c002) as objects
    into v_acls_list
    from apex_collections
    where COLLECTION_NAME = 'SELECTED_OBJECTS'
      and c001 = 'ACL';
      
    select listagg(c002,':') within group (order by c002) as objects
    into v_sclass_list
    from apex_collections
    where COLLECTION_NAME = 'SELECTED_OBJECTS'
      and c001 = 'SCLASS';
      
    select listagg(c002,':') within group (order by c002) as objects
    into v_priveleges_list
    from apex_collections
    where COLLECTION_NAME = 'SELECTED_OBJECTS'
      and c001 = 'PRIV';
      
    select listagg(c002,':') within group (order by c002) as objects
    into v_policies
    from apex_collections
    where COLLECTION_NAME = 'SELECTED_OBJECTS'
      and c001 = 'POL';

    v_statement := v_statement||'SET ECHO OFF'||EOL||
                                'SET SERVEROUTPUT ON'||EOL||EOL;
    
    if p_delete_flag = 'Y' then 
      v_statement := v_statement||export_xs_users(p_list   => v_user_list,
                                                  p_delete => 'Y');   
      v_statement := v_statement||export_xs_regular_roles(p_list   => v_rrole_list,
                                                          p_delete => 'Y');

      v_statement := v_statement||export_xs_dynamic_roles(p_list   => v_drole_list,
                                                          p_delete => 'Y');
                                                          
      v_statement := v_statement||export_priveleges(p_list   => v_priveleges_list,
                                                    p_delete => 'Y');

      v_statement := v_statement||export_security_classes(p_list   => v_sclass_list,
                                                          p_delete => 'Y');
                                                          
      v_statement := v_statement||export_acls(p_list    => v_acls_list,
                                               p_delete => 'Y'); 
                                               
      v_statement := v_statement||export_policies(p_list   => v_policies,
                                                  p_delete => 'Y'); 
    end if;
    v_statement := v_statement||''||EOL;

    v_statement := v_statement||export_xs_regular_roles(p_list => v_rrole_list);

    v_statement := v_statement||export_xs_dynamic_roles(p_list => v_drole_list);

    v_statement := v_statement||export_xs_grants(p_list => v_rrole_list);   
                                                                       
    v_statement := v_statement||export_xs_grants(p_list => v_drole_list);

    v_statement := v_statement||export_xs_users(p_list => v_user_list);   
    
    v_statement := v_statement||export_security_classes(p_list => v_sclass_list);  
    
    v_statement := v_statement||export_security_classes_dep(p_list => v_sclass_list);
    
    v_statement := v_statement||export_priveleges(p_list => v_priveleges_list);

    v_statement := v_statement||export_acls(p_list => v_acls_list); 
    
    v_statement := v_statement||export_acls_inheritance(p_list => v_acls_list); 
    
    v_statement := v_statement||export_policies(p_list => v_policies); 
    
    return v_statement||EOL||'EXIT'||EOL;
 end export_all;
 -------------------------------------------------------------------------------
 
 procedure download_file(p_delete_flag in varchar2)
 is
    v_blob        blob;
    p_data        clob;
    v_desc_offset PLS_INTEGER := 1;
    v_src_offset  PLS_INTEGER := 1;
    v_lang        PLS_INTEGER := 0;
    v_warning     PLS_INTEGER := 0;   
    
 begin
        dbms_lob.createtemporary(v_blob,true);
        p_data := RAS_EXPORT.export_all(p_delete_flag => p_delete_flag);
        dbms_lob.converttoblob(v_blob, p_data, dbms_lob.getlength(p_data), v_desc_offset, v_src_offset, dbms_lob.default_csid, v_lang, v_warning);
        sys.htp.init;
        sys.owa_util.mime_header('text/txt', FALSE );
        sys.htp.p('Content-length: ' || sys.dbms_lob.getlength( v_blob));
        sys.htp.p('Content-Disposition: attachment; filename="ras_export.sql"' );
        sys.owa_util.http_header_close;
        sys.wpg_docload.download_file( v_blob );
        dbms_lob.freetemporary(v_blob);
 exception
     when others then 
        raise_application_error(-20001,'Download file '||SQLERRM);
 end download_file;



END RAS_EXPORT;
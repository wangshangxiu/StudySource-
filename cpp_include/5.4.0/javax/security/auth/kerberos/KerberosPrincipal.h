
// DO NOT EDIT THIS FILE - it is machine generated -*- c++ -*-

#ifndef __javax_security_auth_kerberos_KerberosPrincipal__
#define __javax_security_auth_kerberos_KerberosPrincipal__

#pragma interface

#include <java/lang/Object.h>
extern "Java"
{
  namespace javax
  {
    namespace security
    {
      namespace auth
      {
        namespace kerberos
        {
            class KerberosPrincipal;
        }
      }
    }
  }
}

class javax::security::auth::kerberos::KerberosPrincipal : public ::java::lang::Object
{

public:
  KerberosPrincipal(::java::lang::String *);
  KerberosPrincipal(::java::lang::String *, jint);
private:
  ::java::lang::String * parseRealm();
public:
  ::java::lang::String * getName();
  ::java::lang::String * getRealm();
  jint getNameType();
  jint hashCode();
  jboolean equals(::java::lang::Object *);
  ::java::lang::String * toString();
  static const jint KRB_NT_PRINCIPAL = 1;
  static const jint KRB_NT_SRV_HST = 3;
  static const jint KRB_NT_SRV_INST = 2;
  static const jint KRB_NT_SRV_XHST = 4;
  static const jint KRB_NT_UID = 5;
  static const jint KRB_NT_UNKNOWN = 0;
private:
  ::java::lang::String * __attribute__((aligned(__alignof__( ::java::lang::Object)))) name;
  jint type;
  ::java::lang::String * realm;
public:
  static ::java::lang::Class class$;
};

#endif // __javax_security_auth_kerberos_KerberosPrincipal__

## Requirements  
1. python3  
2. pip packages python_freeipa and pyotp  
3. [openvpn-plugin-auth-script.so](https://github.com/fac/auth-script-openvpn)  
4. correct time on server with script  
5. a pre-created user in freeipa, added to the `freeipa_group_required` group, as well as an added token, via OTP Tokens -> add -> TOTP token from the user  
6. user with admin rights or read user secrets 

### How To OpenVPN  

Add to you server openvpn.conf:  
```
client-cert-not-required
username-as-common-name
plugin /location/to/you/openvpn-plugin-auth-script.so /location/to/you/ovpn_2fa_auth_sript.py
setenv freeipa_group_required vpn_it;
setenv freeipa_replica freeipa-replica.you_domain.com;
setenv freeipa_admin ovpn-2fa-service;
setenv freeipa_admin_password SUPERPASSWORD;
```
  
Add to you client openvpn.conf:  
```
static-challenge "Enter 2fa PIN" 1
```
### How does it work:  

1. Openvpn transmits `username`, `password`, `auth_control_file` through environment variables, where `password` is a string like `SCRV1:base64password:base64pin`, `auth_control_file` is a tmp file monitored by the ovpn daemon, we must write 1 to it in case of successful authorization, 0 in case of failure. It is also necessary that our script completes without errors  
2. Script decodes payload from ENV `password`  
2. The script binds the user with the transferred credentials  
3. The script checks if a user is in a specific group  
4. The script checks the OTP pin code of the user under the service account  
5. If **all conditions** are successful, writes 1 to `auth_control_file`, otherwise writes 0  
6. The script exits with code 0 if there were no errors  

## OTHER:  
The script writes logs to `/var/log/ovpn_2fa_auth_script.log`    
This script was also tested with pfsense 2.7.2  
Setenv via openvpn is used so that one script can be used by many openvpn servers at the same time, for example, checking different freepa groups for a user
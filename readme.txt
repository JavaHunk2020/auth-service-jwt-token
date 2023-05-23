D:\cert>keytool -genkey -alias keubiko -keyalg RSA -keystore kuebiko.keystore
Enter keystore password:
Re-enter new password:
What is your first and last name?
  [Unknown]:  localhost
What is the name of your organizational unit?
  [Unknown]:  KUEBIKO
What is the name of your organization?
  [Unknown]:  DEVELOPMENT
What is the name of your City or Locality?
  [Unknown]:  Dalls
What is the name of your State or Province?
  [Unknown]:  TEXAS
What is the two-letter country code for this unit?
  [Unknown]:  US
Is CN=localhost, OU=KUEBIKO, O=DEVELOPMENT, L=Dalls, ST=TEXAS, C=US correct?
  [no]:  yes


D:\cert>keytool -export -alias keubiko -keystore kuebiko.jks -file publickey.pem
keytool error: java.lang.Exception: Keystore file does not exist: kuebiko.jks

D:\cert>keytool -export -alias keubiko -keystore kuebiko.keystore -file publickey.pem
Enter keystore password:
Certificate stored in file <publickey.pem>

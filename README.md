# Cypher Log4j 1.2 Example

This code generates a ramdom password for each file of a Log4j 1.2 RollingFileAppender.

The password in encrypted using RSA and stored in a file next to the log file.

Then RollingFileAppender is subclassed to cypher its contents using the encrypted password.

Public and private keys may be read from files of from a JKS key store.


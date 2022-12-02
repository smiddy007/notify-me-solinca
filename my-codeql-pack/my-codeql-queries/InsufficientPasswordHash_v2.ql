/**
 * @name Use of password hash with insufficient computational effort
 * @description Creating a hash of a password with low computational effort makes the hash vulnerable to password cracking attacks.
 * @kind problem
 * @problem.severity warning
 * @security-severity 8.1
 * @precision high
 * @id js/insufficient-password-hash
 * @tags security
 *       external/cwe/cwe-916
 */
  
import javascript
private import semmle.javascript.security.dataflow.InsufficientPasswordHashCustomizations::InsufficientPasswordHash
private import semmle.javascript.security.SensitiveActions

#from CleartextPasswordSource cps
from InsufficientPasswordHashAlgorithm ipha 

#select cps, cps.describe()
select ipha, ipha.describe()

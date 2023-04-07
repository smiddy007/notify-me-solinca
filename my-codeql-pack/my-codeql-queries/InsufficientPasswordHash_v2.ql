/**
 * @name Use of password hash with insufficient computational effort
 * @description Creating a hash of a password with low computational effort makes the hash vulnerable to password cracking attacks.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 8.1
 * @precision high
 * @id js/insufficient-password-hash
 * @tags security
 *       external/cwe/cwe-916
 */

import javascript
import semmle.javascript.security.dataflow.InsufficientPasswordHashQuery
import DataFlow::PathGraph
import semmle.javascript.security.internal.CryptoAlgorithmNames

// Holds if `algorithm` is an `EncryptionAlgorithm` that uses a block cipher
private predicate isBlockEncryptionAlgorithm(CryptographicAlgorithm algorithm) {
  algorithm instanceof EncryptionAlgorithm and
  not algorithm.(EncryptionAlgorithm).isStreamCipher()
}

private class InstantiatedAlgorithm extends DataFlow::CallNode {
  private string algorithmName;

  InstantiatedAlgorithm() {
    /*
     *       ```
     *       const crypto = require("crypto-js");
     *       const cipher = crypto.algo.SHA256.create();
     *       ```
     *       matched as:
     *       ```
     *       const crypto = require("crypto-js");
     *       const cipher = crypto.algo.<algorithmName>.create();
     *       ```
     */

    this =
      API::moduleImport("crypto-js")
          .getMember("algo")
          .getMember(algorithmName)
          .getMember("create")
          .getACall() and
    not isStrongPasswordHashingAlgorithm(algorithmName)
  }

  CryptographicAlgorithm getAlgorithm() { result.matchesName(algorithmName) }

  private BlockMode getExplicitBlockMode() { result.matchesString(algorithmName) }

    BlockMode getBlockMode() {
      isBlockEncryptionAlgorithm(this.getAlgorithm()) and
      (
        if exists(this.getExplicitBlockMode())
        then result = this.getExplicitBlockMode()
        else
          // CBC is the default if not explicitly specified
          result = "CBC"
      )
    }
}

/**
   *  Matches `CryptoJS.<algorithmName>` and `require("crypto-js/<algorithmName>")`
   */
  private API::Node getAlgorithmNode(CryptographicAlgorithm algorithm) {
    exists(string algorithmName | algorithm.matchesName(algorithmName) |
      result = API::moduleImport("crypto-js").getMember([algorithmName, "Hmac" + algorithmName])
      or
      result = API::moduleImport("crypto-js/" + algorithmName)
    )
  }

private API::CallNode getEncryptionApplication(API::Node input, CryptographicAlgorithm algorithm) {
  /*
   *    ```
   *    var CryptoJS = require("crypto-js");
   *    CryptoJS.AES.encrypt('my message', 'secret key 123');
   *    ```
   *    Matched as:
   *    ```
   *    var CryptoJS = require("crypto-js");
   *    CryptoJS.<algorithmName>.encrypt(<input>, 'secret key 123');
   *    ```
   *    Also matches where `CryptoJS.<algorithmName>` has been replaced by `require("crypto-js/<algorithmName>")`
   */

  result = getAlgorithmNode(algorithm).getMember("encrypt").getACall() and
  input = result.getParameter(0)
}

private API::CallNode getDirectApplication(API::Node input, CryptographicAlgorithm algorithm) {
  /*
   *    ```
   *    var CryptoJS = require("crypto-js");
   *    CryptoJS.SHA1("Message", "Key");
   *    ```
   *    Matched as:
   *    ```
   *    var CryptoJS = require("crypto-js");
   *    CryptoJS.<algorithmName>(<input>, "Key");
   *    ```
   *    An `Hmac`-prefix of <algorithmName> is ignored.
   *    Also matches where `CryptoJS.<algorithmName>` has been replaced by `require("crypto-js/<algorithmName>")`
   */

  result = getAlgorithmNode(algorithm).getACall() and
  input = result.getParameter(0)
}

private API::CallNode getUpdatedApplication(API::Node input, InstantiatedAlgorithm instantiation) {
  /*
   *    ```
   *    var CryptoJS = require("crypto-js");
   *    var hash = CryptoJS.algo.SHA256.create();
   *    hash.update('message');
   *    hash.update('password');
   *    var hashInHex = hash.finalize();
   *    ```
   *    Matched as:
   *    ```
   *    var CryptoJS = require("crypto-js");
   *    var hash = CryptoJS.algo.<algorithmName>.create();
   *    hash.update(<input>);
   *    hash.update(<input>);
   *    var hashInHex = hash.finalize();
   *    ```
   *    Also matches where `CryptoJS.algo.<algorithmName>` has been
   *    replaced by `require("crypto-js/<algorithmName>")`
   */

  result = instantiation.getAMemberCall("update") and
  input = result.getParameter(0)
}

private class Apply extends CryptographicOperation::Range instanceof API::CallNode {
  API::Node input;
  CryptographicAlgorithm algorithm; // non-functional

  Apply() {
    this = getEncryptionApplication(input, algorithm)
    or
    this = getDirectApplication(input, algorithm)
    or
    exists(InstantiatedAlgorithm instantiation |
      this = getUpdatedApplication(input, instantiation) and
      algorithm = instantiation.getAlgorithm()
    )
  }

  override DataFlow::Node getAnInput() { result = input.asSink() }

  override CryptographicAlgorithm getAlgorithm() { result = algorithm }

  private BlockMode getExplicitBlockMode() {
    exists(string modeString |
      API::moduleImport("crypto-js").getMember("mode").getMember(modeString).asSource() =
        super.getParameter(2).getMember("mode").asSink()
    |
      result.matchesString(modeString)
    )
  }

  override BlockMode getBlockMode() {
    isBlockEncryptionAlgorithm(this.getAlgorithm()) and
    (
      if exists(this.getExplicitBlockMode())
      then result = this.getExplicitBlockMode()
      else
        // CBC is the default if not explicitly specified
        result = "CBC"
    )
  }
}

from Configuration cfg, DataFlow::PathNode source, Apply apply
where cfg.isSource(source.getNode())
select source, source.getNode(), source.getNode().(Source).describe(), apply

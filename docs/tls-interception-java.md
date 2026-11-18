# TLS Interception by Corporate Proxies and Java Trust Stores

## The problem

In many corporate networks, a Java application that connects to a remote HTTPS
service through the company proxy fails the TLS handshake with an error such as:

```
javax.net.ssl.SSLHandshakeException: PKIX path building failed:
sun.security.provider.certpath.SunCertPathBuilderException:
unable to find valid certification path to requested target
```

Looking at the certificate the client actually received, the **issuer is not a
public CA** but a corporate one (for example "Contoso Proxy Root CA"). That root
is not in the JDK's bundled trust store (`$JAVA_HOME/lib/security/cacerts`), so
Java refuses the connection.

## Why the proxy does this

What you're seeing is **TLS interception**, also called SSL inspection or
break-and-inspect. It's done by products like Zscaler, Palo Alto, Netskope,
Blue Coat/Symantec and Fortinet. In effect it's a man-in-the-middle that the
company has approved:

```
 Java client                Corporate proxy                 api.example.com
     |                            |                                |
     |--- TLS ClientHello ------->|                                |
     |                            |--- TLS ClientHello ----------->|
     |                            |<-- real cert (public CA) ------|
     |                            |    (proxy validates it)        |
     |<-- minted cert for --------|                                |
     |    api.example.com,        |                                |
     |    signed by corporate CA  |                                |
     |                            |                                |
     |==== TLS session A ========>| decrypt / inspect / re-encrypt |
     |                            |==== TLS session B ============>|
```

1. Your Java client opens a TLS session to `api.example.com`, but the proxy
   answers that handshake itself.
2. The proxy opens its own, separate TLS session to the real `api.example.com`
   and checks the real server's certificate.
3. The proxy creates a new certificate for `api.example.com` on the spot. It
   signs that certificate with the **corporate CA's private key** and presents
   it to you.
4. Traffic is decrypted at the proxy, inspected, and encrypted again in both
   directions.

### Why companies do it

Most traffic today is HTTPS. Without decrypting it, the proxy only sees the
hostname (through SNI or the `CONNECT` request). Decrypting lets security teams:

- scan downloads for malware
- run data-loss prevention, such as blocking uploads of source code, customer
  data or credit-card numbers
- filter by full URL or content, not just by domain
- spot command-and-control traffic and data being sent out
- keep audit logs for compliance

### Why browsers work but Java doesn't

IT pushes the corporate root CA into the **Windows certificate store** through
Group Policy or Intune. Edge and Chrome trust that store. Java ignores it by
default and uses its own bundled `cacerts`, which only contains public CAs.

## Can the proxy present the real server certificate instead?

**Not while it is inspecting the traffic.** A certificate is only half of what
TLS needs. During the handshake the server must prove it holds the private key
matching the certificate's public key. The proxy doesn't have
`api.example.com`'s private key. If it forwarded the real certificate, it
couldn't complete the handshake. Your client would reject it, and that
rejection is exactly what TLS is designed to do.

What the proxy **can** do is **skip inspection for specific destinations**.
Every interception product has a bypass list (names vary: "SSL bypass", "do not
decrypt", "SSL inspection exemption"). For a bypassed host, the proxy just
passes the encrypted bytes through a `CONNECT` tunnel, and your client sees the
real certificate. This is the usual fix for:

- apps that pin certificates
- **mutual TLS (mTLS)**, because the proxy can't pass your client certificate
  along
- sensitive categories such as banking and healthcare

That's a request to your network or security team, usually with a business
justification. Whether they agree is a policy decision, not a technical one.

## Option 1: use the Windows root store from the JVM

Java on Windows includes the `SunMSCAPI` provider, which exposes the Windows
certificate store as a KeyStore type:

```powershell
java "-Djavax.net.ssl.trustStoreType=Windows-ROOT" -jar app.jar
```

To apply it to every JVM you start, without changing each command line:

```powershell
setx JAVA_TOOL_OPTIONS "-Djavax.net.ssl.trustStoreType=Windows-ROOT"
```

Things to know:

- **It replaces `cacerts`; it doesn't add to it.** This is usually fine,
  because Windows also trusts the public roots. Windows fetches missing public
  roots on demand, though, so a root that has never been used on that machine
  may not be in the store yet. This occasionally causes a failure for some
  uncommon public CA.
- `Windows-ROOT` reads the **current user's** root store, which also shows the
  machine-wide roots pushed by Group Policy. Newer JDKs (around 24 and later)
  also add `Windows-ROOT-LOCALMACHINE` and `Windows-ROOT-CURRENTUSER` to pick
  one store explicitly. That matters for services running as a different
  account.
- This only covers code that uses the JDK's default `SSLContext` or
  `TrustManagerFactory`. That includes `HttpsURLConnection`,
  `java.net.http.HttpClient`, and Apache HttpClient and OkHttp in their default
  setup. It doesn't cover libraries that bring their own trust store, such as
  Netty with its own OpenSSL setup or some database drivers, or tools with
  separate settings like Gradle and Maven wrappers.
- It only works on Windows. A container or Linux CI agent running the same app
  needs Option 2.

## Option 2: add the corporate CA to a Java trust store

This works on any platform.

**Get the CA certificate**, either:

- from `certmgr.msc` → *Trusted Root Certification Authorities* → export the
  corporate root as Base-64 `.cer`, or
- by capturing the chain through the proxy:

  ```powershell
  openssl s_client -proxy proxy.corp.example:8080 -connect api.example.com:443 -showcerts
  ```

**Then either import it into the JDK's `cacerts`:**

```powershell
keytool -importcert -cacerts -alias corp-proxy-ca -file corp-root.cer
```

**or, better, because it survives JDK upgrades,** create a separate trust store
that contains a copy of `cacerts` plus the corporate CA, and point the JVM at it:

```powershell
java "-Djavax.net.ssl.trustStore=C:\certs\corp-truststore.p12" "-Djavax.net.ssl.trustStorePassword=changeit" -jar app.jar
```

## What not to do

Don't fix this by turning off certificate validation (a trust-all
`TrustManager` or disabling hostname verification). That leaves the app open to
a real attacker, not just the approved proxy.

## Summary

| Question | Answer |
|---|---|
| Why does the proxy replace the certificate? | It terminates TLS to inspect traffic (malware, DLP, URL filtering, auditing) and re-signs with the corporate CA. |
| Can it present the real server certificate? | Not while inspecting — it lacks the server's private key. It can **bypass** inspection for specific hosts. |
| Why does Java fail when browsers work? | Java uses its own `cacerts`, not the Windows store where IT installed the corporate root. |
| Can the JVM use the Windows root store? | Yes: `-Djavax.net.ssl.trustStoreType=Windows-ROOT` (Windows only). |
| Portable fix? | Add the corporate CA to a custom trust store and set `javax.net.ssl.trustStore`. |

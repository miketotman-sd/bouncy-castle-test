#! /bin/sh

# Enable TLS v1.2
JAVA_OPTS="$JAVA_OPTS -Djdk.tls.client.protocols=TLSv1,TLSv1.1,TLSv1.2"
JAVA_OPTS="$JAVA_OPTS -Dhttps.protocols=TLSv1,TLSv1.1,TLSv1.2"

# Enable handshake debugging
JAVA_OPTS="$JAVA_OPTS -Djavax.net.debug=ssl:handshake:verbose"

echo JAVA_OPTS=\'"$JAVA_OPTS"\'

export JAVA_OPTS


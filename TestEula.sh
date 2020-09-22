#! /bin/bash
#JAVA_OPTS="-Djdk.tls.client.protocols=TLSv1.2 -Dhttps.protocols=TLSv1.2"
#JAVA_OPTS="$JAVA_OPTS -Djavax.net.debug=ssl:handshake:verbose"
pushd bin ; java -Djavax.net.debug=ssl,handshake:verbose -cp ".:../bc/bcprov-jdk15to18-166.jar:../bc/bctls-jdk15to18-166.jar" $1 ; popd
#java -cp ".:./bc/crypto-166/jars/bctls-jdk15on-166.jar" $1
#java -Djdk.tls.client.protocols=TLSv1,TLSv1.1,TLSv1.2 -Dhttps.protocols=TLSv1,TLSv1.1,TLSv1.2 -Djavax.net.debug=ssl:handshake:verbose -cp "./bc/crypto-166/jars/bctls-jdk15on-166.jar:." sdpm.$1
#java -Djdk.tls.client.protocols=TLSv1,TLSv1.1,TLSv1.2 -Dhttps.protocols=TLSv1,TLSv1.1,TLSv1.2 -Dhttps.cipherSuites=TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 -Djavax.net.debug=ssl:handshake:verbose $1
#java -Djdk.tls.client.protocols=TLSv1,TLSv1.1,TLSv1.2 -Dhttps.protocols=TLSv1,TLSv1.1,TLSv1.2 $1

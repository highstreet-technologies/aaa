#!/bin/bash

VERSION="0.17.11"
RELEASE_URL="https://s01.oss.sonatype.org/service/local/staging/deploy/maven2"
SERVERID=sonatype
NAME="aaa-authn-api"


echo "Deloy artifact $NAME to server $SERVERID with parameters below:"
echo "  Version: $VERSION"
echo "  RELEASE_URL: $RELEASE_URL"

read -r -p "Are you sure? [y/N] " response
response=${response,,}    # tolower
if [[ "$response" == "y" || "$response" == "Y" || "$response" == "yes" || "$response" == "Yes" ]] ; then
  echo "deploy .."
  mvn gpg:sign-and-deploy-file \
      -DpomFile=pom.xml \
      -Dfile=target/$NAME-$VERSION.jar \
      -Dsources=target/$NAME-$VERSION-sources.jar \
      -Djavadoc=target/$NAME-$VERSION-javadoc.jar \
      -Durl=$RELEASE_URL \
      -DrepositoryId=$SERVERID
else
  echo "terminated"
fi
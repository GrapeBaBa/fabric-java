#!/bin/bash
# This script will build the project.

if [ "$TRAVIS_PULL_REQUEST" != "false" ]; then
  echo -e "Build Pull Request #$TRAVIS_PULL_REQUEST => Branch [$TRAVIS_BRANCH]"
  ./gradlew -Prelease.useLastTag=true build
elif [ "$TRAVIS_PULL_REQUEST" == "false" ] && [ "$TRAVIS_TAG" == "" ]; then
  echo -e 'Build Branch with Snapshot => Branch ['$TRAVIS_BRANCH']'
  ./gradlew -Prelease.travisci=true -PbintrayUser="${BINTRAY_USER}" -PbintrayKey="${BINTRAY_PASSWORD}" -PsonatypeUsername="${SONATYPE_USER}" -PsonatypePassword="${SONATYPE_PASSWORD}" -Prelease.scope=patch build snapshot --stacktrace
elif [ "$TRAVIS_PULL_REQUEST" == "false" ] && [ "$TRAVIS_TAG" != "" ]; then
  echo -e 'Build Branch for Release => Branch ['$TRAVIS_BRANCH']  Tag ['$TRAVIS_TAG']'
  ./gradlew -Prelease.travisci=true -Prelease.useLastTag=true -PbintrayUser="${BINTRAY_USER}" -PbintrayKey="${BINTRAY_PASSWORD}" -PsonatypeUsername="${SONATYPE_USER}" -PsonatypePassword="${SONATYPE_PASSWORD}" final --stacktrace
else
  echo -e 'WARN: Should not be here => Branch ['$TRAVIS_BRANCH']  Tag ['$TRAVIS_TAG']  Pull Request ['$TRAVIS_PULL_REQUEST']'
  ./gradlew -Prelease.useLastTag=true build
fi
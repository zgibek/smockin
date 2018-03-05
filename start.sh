#!/bin/sh

# Check Java 8 is installed
SMOCKIN_JAVA_VERSION=$(java -version 2>&1 | grep -i version | sed 's/.*version ".*\.\(.*\)\..*"/\1/; 1q')

if [ "${SMOCKIN_JAVA_VERSION}" \< 8 ]
then
  echo ""
  echo "Smockin requires Java 8 or later to run"
  echo ""
  echo "Please visit 'http://www.java.com/en/download' to install the latest Java Runtime Environment (JRE)"
  echo ""
  echo "If you have installed Java and are still seeing this message, then please ensure this is present in your PATH"
  echo ""

  exit
fi



APP_NAME="SMOCKIN"
APP_VERSION="1.3.1-SNAPSHOT"
DEBUG_PORT=8008

APP_DIR_PATH="${HOME}/.smockin"
DB_DIR_PATH="${APP_DIR_PATH}/db"
PIDS_DIR_PATH="${APP_DIR_PATH}/pids"
DB_DRIVER_DIR_PATH="${DB_DIR_PATH}/driver"
DB_DATA_DIR_PATH="${DB_DIR_PATH}/data"
DB_MARKER="db_initialized"
H2_JAR_NAME="h2-1.4.194.jar"
DB_PROPS_FILE=db.properties
APP_PROPS_FILE=app.properties
SMOCKIN_PID_FILE="$PIDS_DIR_PATH/smockin-app.pid"
H2_DB_PID_FILE="$PIDS_DIR_PATH/smockin-db.pid"

USE_DEBUG=false
USE_INMEM_DB=false

if [ ! -d "${APP_DIR_PATH}" ]
then
  echo ""
  echo "Please run the install.sh script first to install required .smockin config to your user home"
  echo ""
  exit
fi




#
# Check if smockin already has a pid.
if [ -f $SMOCKIN_PID_FILE ];
then
    echo "SMOCKIN is already running"
    exit 0
fi

# DB properties
DB_PROPS_FILE=$(grep "^[^#;]" ${DB_DIR_PATH}/${DB_PROPS_FILE})

DB_USERNAME=$(echo "$DB_PROPS_FILE" | grep "DB_USERNAME" | awk '{ print $3 }')
DB_PASSWORD=$(echo "$DB_PROPS_FILE" | grep "DB_PASSWORD" | awk '{ print $3 }')
DRIVER_CLASS=$(echo "$DB_PROPS_FILE" | grep "DRIVER_CLASS" | awk '{ print $3 }')
JDBC_URL=$(echo "$DB_PROPS_FILE" | grep "JDBC_URL" | awk '{ print $3 }')
HIBERNATE_DIALECT=$(echo "$DB_PROPS_FILE" | grep "HIBERNATE_DIALECT" | awk '{ print $3 }')
MAX_POOL_SIZE=$(echo "$DB_PROPS_FILE" | grep "MAX_POOL_SIZE" | awk '{ print $3 }')
MIN_POOL_SIZE=$(echo "$DB_PROPS_FILE" | grep "MIN_POOL_SIZE" | awk '{ print $3 }')

# APP properties
APP_PROPS_FILE=$(grep "^[^#;]" ${APP_DIR_PATH}/${APP_PROPS_FILE})

H2_PORT=$(echo "$APP_PROPS_FILE" | grep "H2_PORT" | awk '{ print $3 }')
APP_PORT=$(echo "$APP_PROPS_FILE" | grep "APP_PORT" | awk '{ print $3 }')



if ([ ! -z "$1" ] && [ $1 = "-DEBUG" ]) || ([ ! -z "$2" ] && [ $2 = "-DEBUG" ]); then
    USE_DEBUG=true
fi

if ([ ! -z "$1" ] && [ $1 = "-INMEM" ]) || ([ ! -z "$2" ] && [ $2 = "-INMEM" ]); then
    USE_INMEM_DB=true
    JDBC_URL='jdbc:h2:mem:smockindev'
fi



echo "#####################################################################################"
echo "# "
echo "#  $APP_NAME v$APP_VERSION"
echo "#  "


#
# Check for H2 DB Server driver and start it up (in TCP server mode) if not already running
#
if ([ $DRIVER_CLASS = "org.h2.Driver" ] && [ !$USE_INMEM_DB ]);
then

  H2_PID=$(ps aux | grep h2 | grep -v grep | awk '{print $2}')
  JDBC_URL=$(echo $JDBC_URL | sed "s/{H2.PORT}/$H2_PORT/g")

  if [ ! -z "$H2_PID" ] 
  then
    echo "#  H2 TCP Database is already running..."
  else
    echo "#  Starting H2 TCP Database..."
    java -cp $DB_DRIVER_DIR_PATH/$H2_JAR_NAME org.h2.tools.Server -tcp -web -webAllowOthers -tcpAllowOthers -tcpPort $H2_PORT > /dev/null 2>&1 &
    echo "$!" > $H2_DB_PID_FILE
  fi

fi


echo "#  JDBC Connectivity Properties:"
echo "#  - JDBC DRIVER: $DRIVER_CLASS"
echo "#  - JDBC URL: $JDBC_URL"
echo "#"


#
# Prepare runtime args
#
VM_ARGS="-Dspring.datasource.url=$JDBC_URL -Dspring.datasource.username=$DB_USERNAME -Dspring.datasource.password=$DB_PASSWORD -Dspring.datasource.maximumPoolSize=$MAX_POOL_SIZE -Dspring.datasource.minimumIdle=$MIN_POOL_SIZE -Duser.timezone=UTC -Dapp.version=$APP_VERSION"
APP_PROFILE="production"

if ( $USE_INMEM_DB ); then
  APP_PROFILE=""
fi




#
# START UP SMOCKIN APPLICATION
# (JPA WILL CREATE THE ACTUAL SMOCKIN DB AUTOMATICALLY IF IT DOES NOT ALREADY EXIST)
#
echo "#"
echo "#  Starting Main Application..."
echo "#"
echo "#  Please Note:"
echo "#  - Application logs are available from: .smockin/log (under the user.home directory)"
echo "#  - Navigate to: 'http://localhost:$APP_PORT/index.html' to access the Smockin Admin UI."


####### Modes #######
#
# Running 'start.sh' with no argument starts the application asynchronously in the background using the main (H2 TCP) DB.
#
# Note, these commands can be combined.
# (i.e 'start.sh -DEBUG' will enable the debug port and use the main DB, whereas 'start.sh -DEBUG -INMEM' will do the same but with an in mem DB.)
#
# -DEBUG            Allows remote debugging
# -INMEM            Uses an in-memory DB
#
#


if ( $USE_DEBUG ); then
  mvn spring-boot:run -Drun.jvmArguments="-Dspring.profiles.active=$APP_PROFILE -Dserver.port=$APP_PORT $VM_ARGS -Xdebug -Xrunjdwp:transport=dt_socket,server=y,suspend=y,address=$DEBUG_PORT"
else
  echo "#  - Run 'shutdown.sh' when you wish to terminate this application."
  mvn spring-boot:run -Drun.jvmArguments="-Dspring.profiles.active=$APP_PROFILE -Dserver.port=$APP_PORT $VM_ARGS" > /dev/null 2>&1 &
  echo "$!" > $SMOCKIN_PID_FILE
fi

echo "#"
echo "#####################################################################################"

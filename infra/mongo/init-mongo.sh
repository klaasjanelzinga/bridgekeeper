mongo -- "$MONGO_INITDB_DATABASE" <<EOF
    use admin
    var rootUser = '$MONGO_INITDB_ROOT_USERNAME';
    var rootPassword = '$MONGO_INITDB_ROOT_PASSWORD';
    var admin = db.getSiblingDB('admin');
    admin.auth(rootUser, rootPassword);

    var user = '$MONGO_USER';
    var password = '$MONGO_PASS';
    var database = '$MONGO_DB';

    use linkje
    db.createUser({user: user, pwd: password, roles: ["readWrite"]});

    db.grantRolesToUser(
      user,
      [
        { role: "readWrite", db: database }
      ]
    )

    var user = '$MONGO_TEST_USER';
    var password = '$MONGO_TEST_PASS';
    var database = '$MONGO_TEST_DB';

    use linkje-test
    db.createUser({user: user, pwd: password, roles: ["readWrite"]});

    db.grantRolesToUser(
      user,
      [
        { role: "readWrite", db: database }
      ]
    )

EOF%
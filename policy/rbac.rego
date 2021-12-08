package rbac.authz

# user-role assignments
# ユーザーと役割の割り当て
user_roles := {
    "sunjin": ["engineering", "serverdev"],
    "bob": ["hr"],
    "alice": ["enginnering", "webdev"],
}

# role-permissions assignments
# 役割権限の割り当て
role_permissions := {
    "engineering": [ # TODO mapで実装できるかどうかを調べる(listだと、増えたときにコストが高くなる)
        {"action": "read", "object": "server123"},
    ],
    "webdev": [
        {"action": "read", "object": "server123"},
        {"action": "write", "object": "server123"}
    ],
    "hr": [
        {"action": "read", "object": "database456"}
    ]
}

# logic that implements RBAC
default allow = false
allow {
    # lookup the list of roles for the user
    # ユーザーの役割リストを検索
    roles := user_roles[input.user]

    # for each role in that list
    # 役割ごとに検証
    r := roles[_]

    # 格roleのpermissionを調べる
    permissions := role_permissions[r]

    # permissionごとにチェック
    p := permissions[_]

    # 権限のcheck
    p == {"action": input.action, "object": input.object}
}

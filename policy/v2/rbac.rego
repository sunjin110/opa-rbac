package rbac.authz

# logic that implements RBAC
default allow = false
allow {
    # lookup the list of roles for the user
    # ユーザーの役割リストを検索
    roles := data.user_roles[input.user]

    # for each role in that list
    # 役割ごとに検証
    r := roles[_]

    # 格roleのpermissionを調べる
    permissions := data.role_permissions[r]

    # permissionごとにチェック
    p := permissions[_]

    # 権限のcheck
    p == {"action": input.action, "object": input.object}
}

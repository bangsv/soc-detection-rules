name: Server_List
type: 1
fillType: Registry
userCanEditContent: true
fields:
  - ip:
      type: String
      primaryKey: true
      index: true
      nullable: false
  - fqdn:
      type: String
      index: false
      nullable: false
      primaryKey: false
      unique: false
defaults:
  PT:
    - ip: 192.168.0.10
      fqdn: dc01.work.local

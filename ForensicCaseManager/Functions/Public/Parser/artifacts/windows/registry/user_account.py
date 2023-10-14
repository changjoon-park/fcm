import json
from typing import Generator

from dissect import cstruct
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.exceptions import RegistryValueNotFoundError

from forensic_artifact import Source, ForensicArtifact

c_sam_def = """
struct user_F {
  char      unknown1[8];
  uint64    t_last_login;           /* Time of last login */
  char      unknown2[8];
  uint64    t_last_password_set;    /* Time of last password set */
  char      unknown3[8];
  uint64    t_last_incorrect_login; /* Time of last incorrect password */
  int32     rid;
  char      unknown4[4];
  uint16    ACB_bits;               /* Account type and status flags */
  char      unknown5[2];
  uint16    country_code;
  char      unknown6[2];
  uint16    failedcnt;        /* Count of failed logins, if > than policy it is locked. Resets after successful login */
  uint16    logins;           /* Total logins since creation (max. 0xFFFF = 65535) */
  char      unknown7[0xc];
};
#define ACB_DISABLED   0x0001
#define ACB_HOMDIRREQ  0x0002
#define ACB_PWNOTREQ   0x0004
#define ACB_TEMPDUP    0x0008
#define ACB_NORMAL     0x0010
#define ACB_MNS        0x0020
#define ACB_DOMTRUST   0x0040
#define ACB_WSTRUST    0x0080
#define ACB_SVRTRUST   0x0100
#define ACB_PWNOEXP    0x0200
#define ACB_AUTOLOCK   0x0400
// char *acb_fields[16] = {
//    "Disabled" ,
//    "Homedir req." ,
//    "Passwd not req." ,
//    "Temp. duplicate" ,
//    "Normal account" ,
//    "NMS account" ,
//    "Domain trust act." ,
//    "Wks trust act." ,
//    "Srv trust act" ,
//    "Pwd don't expire" ,
//    "Auto lockout" ,
//    "(unknown 0x08)" ,
//    "(unknown 0x10)" ,
//    "(unknown 0x20)" ,
//    "(unknown 0x40)" ,
//    "(unknown 0x80)" ,
// };
struct user_V {
  int unknown1_1;           /* 0x00 - always zero? */
  int unknown1_2;           /* 0x04 - points to username? */
  int unknown1_3;           /* 0x08 - always 0x02 0x00 0x01 0x00 ? */
  int username_ofs;         /* 0x0c */
  int username_len;         /* 0x10 */
  int unknown2_1;           /* 0x14 - always zero? */
  int fullname_ofs;         /* 0x18 */
  int fullname_len;         /* 0x1c */
  int unknown3_1;           /* 0x20 - always zero? */
  int admin_comment_ofs;    /* 0x24 */
  int admin_comment_len;    /* 0x28 */
  int unknown4_1;           /* 0x2c - alway zero? */
  int user_comment_ofs;     /* 0x30 */
  int user_comment_len;     /* 0x34 */
  int unknown5_1;           /* 0x38 - zero? */
  int unknown5_2;           /* 0x3c - to field 8 bytes before hashes */
  int unknown5_3;           /* 0x40 - zero? or size of above? */
  int unknown5_4;           /* 0x44 - zero? */
  int homedir_ofs;          /* 0x48 */
  int homedir_len;          /* 0x4c */
  int unknown6_1;           /* 0x50 - zero? */
  int drvletter_ofs;        /* 0x54 - drive letter for home dir */
  int drvletter_len;        /* 0x58 - len of above, usually 4   */
  int unknown7_1;           /* 0x5c - zero? */
  int logonscr_ofs;         /* 0x60 - users logon script path */
  int logonscr_len;         /* 0x64 - length of string */
  int unknown8_1;           /* 0x68 - zero? */
  int profilep_ofs;         /* 0x6c - profile path string */
  int profilep_len;         /* 0x70 - profile path stringlen */
  int unknown9_1;           /* 0x74 */
  int workstations_ofs;     /* 0x78 */
  int workstations_len;     /* 0x7c */
  int unknowna_1;          /* 0x80 */
  int allowed_hours_ofs;    /* 0x84 */
  int allowed_hours_len;    /* 0x88 */
  int unknownb_1;          /* 0x8c */
  int unknownb_2;          /* 0x90 - pointer to some place before hashes, after comments */
  int unknownb_3;          /* 0x94 - size of above? */
  int unknownb_4;          /* 0x98 - unknown? always 1? */
  int lmpw_ofs;             /* 0x9c */
  int lmpw_len;             /* 0xa0 */
  int unknownc_1;           /* 0xa4 - zero? */
  int ntpw_ofs;             /* 0xa8 */
  int ntpw_len;             /* 0xac */
  int unknownd_1;           /* 0xb0 */
  int unknownd_2;           /* 0xb4 - points to field after hashes */
  int unknownd_3;           /* 0xb8 - size of above field */
  int unknownd_4;           /* 0xbc - zero? */
  int unknownd_5;           /* 0xc0 - points to field after that */
  int unknownd_6;           /* 0xc4 - size of above */
  int unknownd_7;           /* 0xc8 - zero ? */
  char data[4];             /* Data starts here. All pointers above is relative to this,
                               that is V + 0xCC */
};
struct DOMAIN_ACCOUNT_F {
  uint16 revision;                          /* 0x00 */
  uint16 unknown1_1;                        /* 0x02 */
  uint32 unknown1_2;                        /* 0x04 */
  uint64 creation_time;                     /* 0x08 */
  uint64 domain_modified_count;             /* 0x10 */
  uint64 max_password_age;                  /* 0x18 */
  uint64 min_password_age;                  /* 0x20 */
  uint64 force_logoff;                      /* 0x28 */
  uint64 lock_duration;                     /* 0x30 */
  uint64 lock_observation_window;           /* 0x38 */
  uint64 modified_count_at_last_promotion;  /* 0x40 */
  uint32 next_rid;                          /* 0x48 */
  uint32 password_properties;               /* 0x4c */
  uint16 min_password_length;               /* 0x50 */
  uint16 password_history_length;           /* 0x52 */
  uint16 lockout_threshold;                 /* 0x54 */
  uint16 unknown1_1;                        /* 0x56 */
  uint32 server_state;                      /* 0x58 */
  uint16 server_role;                       /* 0x5c */
  uint16 uas_compability_required;          /* 0x5e */
  uint64 unknown2_1;                        /* 0x60 */
  /* char sam_key[];                           0x70, variable size */
};
struct SAM_KEY {      /* size: 64 */
  uint32 revision;    /* 0x00 */
  uint32 length;      /* 0x04 */
  char salt[16];      /* 0x08 */
  char key[16];       /* 0x18 */
  char checksum[16];  /* 0x28 */
  uint64 reserved;    /* 0x38 */
};
struct SAM_KEY_AES {  /* size: >= 32 */
  uint32 revision;     /* 0x00 */
  uint32 length;       /* 0x04 */
  uint32 checksum_len; /* 0x08 */
  uint32 data_len;     /* 0x0c */
  char salt[16];       /* 0x10 */
  /* char data[];         0x20, variable size */
};
struct SAM_HASH {      /* size: 20 */
  uint16 pek_id;       /* 0x00 */
  uint16 revision;     /* 0x02 */
  /* char hash[16];       0x04, variable size */
};
struct SAM_HASH_AES {  /* size: >=24 */
  uint16 pek_id;        /* 0x00 */
  uint16 revision;      /* 0x02 */
  uint32 data_offset;   /* 0x04 */
  char salt[16];        /* 0x08 */
  /* char data[];          0x18, variable size */
};
"""

c_sam = cstruct.cstruct()
c_sam.load(c_sam_def)

UserAccountRecord = TargetRecordDescriptor(
    "windows/registry/user_account",
    [
        ("uint32", "rid"),
        ("string", "fullname"),
        ("string", "username"),
        ("datetime", "creation"),
        ("datetime", "lastlogin"),
        ("datetime", "lockout"),
        ("uint32", "logins"),
        ("uint32", "failedlogins"),
        ("string", "comment"),
        ("string", "sid"),
        ("string", "home"),
        ("uint32", "flags"),
        ("string", "lm"),
        ("string", "ntlm"),
    ],
)

class UserAccount(ForensicArtifact):
    """SAM plugin."""

    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(
            src=src,
            artifact=artifact,
            category=category
        )

    def parse(self, descending: bool = False):
        user_account = [
            json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
            for record in self.user_account()
        ]
        
        self.result = {
            "user_account": user_account,
        }

    def user_account(self) -> Generator[UserAccountRecord, None, None]:
        """Return the content of SAM hive registry keys.

        The Security Account Manager (SAM) registry hive contains registry keys that store usernames, full names and
        passwords in a hashed format, either an LM or NTLM hash.

        Sources:
            - https://en.wikipedia.org/wiki/Security_Account_Manager

        Yields SamRecords with fields:
            hostname: The target hostname.
            domain: The target domain.
            rid: The RID.
            fullname: Parsed fullname.
            username: Parsed username.
            comment: Parsed comment.
            lockout: Parsed lockout.
            creation: Parsed lockout.
            lastlogin: Parsed last login.
            flags: Parsed flags.
            failedlogins: Parsed failed logins.
            logins: Parsed logins.
            lm: Parsed LM.
            ntlm: Parsed NTLM.
        """
        for reg_path in self._iter_key(name="Users"):
            for users_key in self.src.source.registry.keys(reg_path):
                for user_key in users_key.subkeys():
                    if user_key.name == "Names":
                        continue

                    user_f = user_key.value("F").value
                    f = c_sam.user_F(user_f)

                    user_v = user_key.value("V").value
                    d = c_sam.user_V(user_v)

                    u_username = user_v[d.username_ofs + 0xCC : d.username_ofs + 0xCC + d.username_len].decode("utf-16-le")
                    u_fullname = user_v[d.fullname_ofs + 0xCC : d.fullname_ofs + 0xCC + d.fullname_len].decode("utf-16-le")
                    u_comment = user_v[d.comment_ofs + 0xCC : d.comment_ofs + 0xCC + d.comment_len].decode("utf-16-le")
                    u_lmpw = user_v[d.lmpw_ofs + 0xCC : d.lmpw_ofs + 0xCC + d.lmpw_len]
                    u_ntpw = user_v[d.ntpw_ofs + 0xCC : d.ntpw_ofs + 0xCC + d.ntpw_len]

                    yield UserAccountRecord(
                        rid=f.rid,
                        fullname=u_fullname,
                        username=u_username,
                        creation=self.ts.wintimestamp(f.t_creation),
                        lastlogin=self.ts.wintimestamp(f.t_login),
                        lockout=self.ts.wintimestamp(f.t_lockout),
                        logins=f.logins,
                        failedlogins=f.failedcnt,
                        comment=u_comment,
                        sid=None,
                        home=None,
                        flags=f.ACB_bits,
                        lm=u_lmpw.hex(),
                        ntlm=u_ntpw.hex()[-31:],
                        _target=self._target,
                    )

        for reg_path in self._iter_key(name="ProfileList"):
            sids = set()
            for k in self.src.source.registry.keys(reg_path):
                for subkey in k.subkeys():
                    sid = subkey.name
                    if sid in sids:
                        continue

                    sids.add(sid)
                    sid = str(subkey.name)
                    rid = int(sid.split("-")[-1])
                    name = None
                    home = None
                    try:
                        profile_image_path = subkey.value("ProfileImagePath")
                    except RegistryValueNotFoundError:
                        pass
                    else:
                        home = profile_image_path.value
                        name = home.split("\\")[-1]

                    yield UserAccountRecord(
                        rid=rid,
                        fullname=None,
                        username=name,
                        creation=None,
                        lastlogin=None,
                        lockout=None,
                        logins=None,
                        failedlogins=None,
                        comment=None,
                        sid=subkey.name,
                        home=home,
                        flags=None,
                        lm=None,
                        ntlm=None,
                        _target=self._target,
                    )
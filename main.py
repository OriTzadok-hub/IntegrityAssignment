import win32api
import win32con
import win32security


UNTRUSTED_RID = 0x0000
LOW_RID = 0x1000
MEDIUM_RID = 0x2000
HIGH_RID = 0x3000
SYSTEM_RID = 0x4000


# this function determines the integrity level of process rid it recieves.
def determine_integrity_level(process_rid):
    if process_rid == UNTRUSTED_RID:
        print('Untrusted Process')
    elif process_rid == LOW_RID:
        print('Low Integrity Process')
    elif MEDIUM_RID <= process_rid < HIGH_RID:
        print('Medium Integrity Process')
    elif HIGH_RID <= process_rid < SYSTEM_RID:
        print('High Integrity Process')
    elif SYSTEM_RID <= process_rid:
        print('System Integrity Process')


tok = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
if tok:
    sid, attr = win32security.GetTokenInformation(tok, win32security.TokenIntegrityLevel)
    win32api.CloseHandle(tok)
    # extract from the SID (that looks like x-x-x-xxxxx) the last number which is the RID,
    # then convert it from decimal to hex
    sidstr = hex(int((win32security.ConvertSidToStringSid(sid)).split('-')[-1]))
    # convert the string hex number to integer
    sidstr = int(sidstr, base=16)
    determine_integrity_level(sidstr)
else:
    print('Error , could not open the access token')

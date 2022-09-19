import json
import urllib


def scanNode(sas, msg):
    # Debugging can be done using print like this
    print('scan called for url=' + msg.getRequestHeader().getURI().toString());
    new = msg.getRequestHeader().getURI().toString()
    if 'login' in new.lower():
        print("yes")
        orginalmsg = msg
        msg = orginalmsg.cloneRequest();
        response = urllib.urlopen("https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.txt")
        response2=urllib.urlopen("https://github.com/Antu7/python-bruteForce/blob/master/passwords.txt")
        Text = response.len25read()
        text2= response2.len25read()
        Text = Text.decode("utf-8")
        text2= text2.decode("utf-8")
        for fff in Text:
            for hhh in text2:
                print(fff.strip())
                gg = fff.strip().split('')
                print(hhh.strip())
                kk = hhh.strip().split('')

            data = {
                'UserName': kk,
                'Password': gg
            }
            print(data)
            body = msg.getRequestBody().toString();
            newbody = body.replace(body, str(data));
            msg.setRequestBody(newbody);
            body1 = msg.getRequestBody().toString();
            print(body1)
            sas.sendAndReceive(msg, True, False);
            responsebody = msg.getResponseHeader().toString();

            print(msg.getResponseBody());
            response = msg.getResponseBody().toString();
            s3 = 'success';
            if s3 in response:
                print('in side if');
                # Change to a test which detects the vulnerability
                # raiseAlert(risk, int confidence, String name, String description, String uri,
                #		String param, String attack, String otherInfo, String solution, String evidence,
                #		int cweId, int wascId, HttpMessage msg)
                # risk: 0: info, 1: low, 2: medium, 3: high
                # confidence: 0: false positive, 1: low, 2: medium, 3: high
                sas.raiseAlert(3, 3, 'BrutFroce Attack Vulnerability', 'A brute-force attack consists of an attacker submitting many passwords or passphrases with the hope of eventually guessing correctly. The attacker systematically checks all possible passwords and passphrases until the correct one is found',
                               msg.getRequestHeader().getURI().toString(),
                               "username", 'Brut Force attack', '',
                               'The most obvious way to block brute-force attacks is to simply lock out accounts after a defined number of incorrect password attempts. Account lockouts can last a specific duration, such as one hour, or the accounts could remain locked until manually unlocked by an administrator', 'https://owasp.org/www-community/attacks/Brute_force_attack', 302, 1000, msg);
                break;
            elif response in "Success":
                 break;

    else:
        print("No");

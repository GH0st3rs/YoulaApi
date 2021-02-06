# YoulaApi
Reversed API for youla.ru

## Usage

```python
from api import YoulaApi

# if you have token and random device ID (8 hex bytes as string)
youla = YoulaApi(device_id='25abf3444ef71337', token='a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1')

# if you have only phone number
import random, string
def random_txt(count):
    return ''.join([random.choice(string.hexdigits[:-6]) for _ in range(count)])

youla = YoulaApi(device_id=random_txt(16))
youla.startPhoneConfirmation(phone='79999999999')
response = youla.auth(pbone='79999999999', sms_code='you received sms code here')
```

### Change phone number
```python
from api import YoulaApi

# you need to login before, see above
new_phone='Your new phone number here'
youla.startPhoneConfirmationWithVerify(new_phone)
response = youla.confirmPhone(phone=new_phone, sms_code='received sms code here')
if response.get('data').get('verify_mode') == 1:
    print(response.get('data').get('verify_text'))
    youla.postPhoneVerifyApprove(True, new_phone)
else:
    print(response.get('data').get('verify_text'))
```

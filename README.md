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

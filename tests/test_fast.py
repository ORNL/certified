from datetime import datetime, timedelta, timezone

from biscuit_auth import BiscuitBuilder

from certified import encode, CA

def test_sign():
    ca = CA.new(encode.person_name("Andrew Jackson"))
    builder = BiscuitBuilder(
        """user({user_id});
           check if time($time), $time < {expiration};
        """,
        { 'user_id': '1234',
          'expiration': datetime.now(tz=timezone.utc) \
                + timedelta(days=1)
        }
    )
    #builder.set_root_key_id(0)
    sgn = ca.sign_biscuit(builder)
    print(sgn)


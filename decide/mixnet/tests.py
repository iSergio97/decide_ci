from django.test import TestCase
from django.conf import settings
from rest_framework.test import APIClient
from rest_framework.test import APITestCase

from mixnet.mixcrypt import MixCrypt
from mixnet.mixcrypt import ElGamal

from base import mods


class MixnetCase(APITestCase):

    def setUp(self):
        self.client = APIClient()
        mods.mock_query(self.client)

    def tearDown(self):
        self.client = None

    def encrypt_msgs(self, msgs, pk, bits=settings.KEYBITS):
        p, g, y = pk
        k = MixCrypt(bits=bits)
        k.k = ElGamal.construct((p, g, y))

        cipher = [k.encrypt(i) for i in msgs]
        return cipher

    def test_create(self):
        data = {
            "voting": 1,
            "auths": [
                { "name": "auth1", "url": "http://localhost:8000" }
            ]
        }

        response = self.client.post('/mixnet/', data, format='json')
        self.assertEqual(response.status_code, 200)

        key = response.json()
        self.key = key

        self.assertEqual(type(key["g"]), int)
        self.assertEqual(type(key["p"]), int)
        self.assertEqual(type(key["y"]), int)

    def test_shuffle(self):
        self.test_create()

        clear = [2, 3, 4, 5]
        pk = self.key["p"], self.key["g"], self.key["y"]
        encrypt = self.encrypt_msgs(clear, pk)
        data = {
            "msgs": encrypt
        }

        response = self.client.post('/mixnet/shuffle/1/', data, format='json')
        self.assertEqual(response.status_code, 200)

        shuffled = response.json()

        self.assertNotEqual(shuffled, encrypt)

    def test_shuffle2(self):
        self.test_create()

        clear = [2, 3, 4, 5]
        pk = self.key["p"], self.key["g"], self.key["y"]
        encrypt = self.encrypt_msgs(clear, pk)
        data = {
            "msgs": encrypt,
            "pk": self.key
        }

        response = self.client.post('/mixnet/shuffle/1/', data, format='json')
        self.assertEqual(response.status_code, 200)

        shuffled = response.json()

        self.assertNotEqual(shuffled, encrypt)

    def test_decrypt(self):
        self.test_create()

        clear = [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
        pk = self.key["p"], self.key["g"], self.key["y"]
        encrypt = self.encrypt_msgs(clear, pk)

        data = { "msgs": encrypt }

        response = self.client.post('/mixnet/shuffle/1/', data, format='json')
        self.assertEqual(response.status_code, 200)
        shuffled = response.json()
        self.assertNotEqual(shuffled, encrypt)

        data = { "msgs": shuffled }

        response = self.client.post('/mixnet/decrypt/1/', data, format='json')
        self.assertEqual(response.status_code, 200)
        clear2 = response.json()
        self.assertNotEqual(clear, clear2)

        self.assertEqual(sorted(clear), sorted(clear2))

import unittest
class TestBasic(unittest.TestCase):
    def test_import(self):
        try:
            from securecheck import SystemAuditor
            self.assertTrue(True)
        except:
            self.fail("Import failed")
if __name__ == '__main__':
    unittest.main()

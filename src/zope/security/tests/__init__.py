import io


class QuietWatchingChecker:
    # zope.testrunner does not support setUp/tearDownModule,
    # so we use a mixin class to make sure we don't flood stderr
    # with pointless printing when testing watching checkers

    def setUp(self):
        from zope.security import checker
        self.__old_file = checker.CheckerLoggingMixin._file
        checker.CheckerLoggingMixin._file = (
            io.StringIO() if bytes is not str else io.BytesIO())

    def tearDown(self):
        from zope.security import checker
        checker.CheckerLoggingMixin._file = self.__old_file

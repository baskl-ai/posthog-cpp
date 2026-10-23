// Another module for terminate_tests: the exception is thrown and left uncaught
// on its own thread, with no frame of the test program on the stack, like an
// exception inside the host application or another plugin.
#include <stdexcept>
#include <thread>

extern "C" void foreign_throw_on_thread() {
    std::thread([] { throw std::runtime_error("foreign_boom_marker"); }).join();
}

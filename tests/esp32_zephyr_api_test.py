import pytest

from esp32_zephyr_api import Esp32API

# Define a fixture
@pytest.fixture(params=[
    ("tcp", "192.168.0.11", 4242)
])
def esp32_api(request):
    protocol, ipv4, port = request.param
    esp32_api_instance = Esp32API(protocol, ipv4, port)
    return esp32_api_instance


class TestEsp32API:

    def test_ping(self, esp32_api):
        pong = esp32_api.ping()

    def test_version_get(self, esp32_api):
        version = esp32_api.version_get()

    def test_adc_channels_get(self, esp32_api):
        adc_chs = 0
        adc_chs = esp32_api.adc_channels_get()

    def test_pwm_chs_get(self, esp32_api):
        pwm_chs = esp32_api.pwm_chs_get()

    @pytest.mark.parametrize("channel", [0, 1])
    def test_adc_channel_read(self, esp32_api, channel):
        esp32_api.adc_channel_read(channel)

    @pytest.mark.parametrize("channel", [0, 1, 2])
    def test_pwm_get(self, esp32_api, channel):
        esp32_api.pwm_get(channel)

    def test_pwm_periods_get(self, esp32_api):
        esp32_api.pwm_periods_get()

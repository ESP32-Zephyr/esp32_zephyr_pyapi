# --- Imports --- #
import socket
import logging

from google.protobuf.json_format import MessageToDict

from .cmds_pb2 import *

logger = logging.getLogger("esp32_api")
logging.basicConfig(
    level=logging.DEBUG,  # Log DEBUG and above (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # Include timestamp, logger name, etc.
    #filename='_esp32_zephyr_pyapi.log',  # Log to file (omit this to log to console)
    encoding='utf-8'  # Optional: handle non-ASCII characters
)

class Esp32API:
    """
    API for communicating with ESP32 via TCP or UDP sockets using protobuf commands.
    """

    def __init__(self, protocol: str, address: str, port: int):
        """
        Initialize the Esp32API instance and set up connection parameters.
        Args:
            protocol (str): Communication protocol ('tcp' or 'udp').
            address (str): ESP32 IPv4 address.
            port (int): ESP32 port number.
        """
        """
        Initialize connection to ESP32.
        :param protocol: 'tcp' or 'udp'
        :param address: ESP32 IPv4 address as string
        :param port: ESP32 port as integer
        """
        self.protocol = protocol.lower()
        self.addr = (address, port)

        self.sock_send_hndlr = {
            "tcp": self._sock_tcp_send,
            "udp": self._sock_udp_send
        }

    def _sock_tcp_send(self, req_raw: bytearray):
        """
        Send a request via TCP and receive the response.
        Args:
            req_raw (bytearray): Serialized request data.
        Returns:
            bytes or None: Response data or None if timeout occurs.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5.0)
            s.connect(self.addr)
            s.send(req_raw)
            try:
                return s.recv(1024)
            except socket.timeout:
                logger.warning("Receive timeout")
                return None

    def _sock_udp_send(self, req_raw: bytearray):
        """
        Send a request via UDP and receive the response.
        Args:
            req_raw (bytearray): Serialized request data.
        Returns:
            bytes or None: Response data or None if timeout occurs.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5.0)
            s.sendto(req_raw, self.addr)
            try:
                res_raw, _ = s.recvfrom(1024)
                return res_raw
            except socket.timeout:
                logger.warning("Receive timeout")
                return None

    def send_cmd(self, req: object, req_id: int):
        """
        Serialize and send a protobuf request, then wait for and parse the response.
        Args:
            req (object): Protobuf request object.
            req_id (int): Command ID.
        Returns:
            response or None: Parsed response object or None if parsing fails.
        """
        """
        Serialize and send protobuf request, then wait for and parse response.
        """
        res = response()
        req.hdr.id = req_id
        req_raw = req.SerializeToString()
        logger.debug(f"--->\n{req}")
        res_raw = self.sock_send_hndlr[self.protocol](req_raw)
        try:
            res.ParseFromString(res_raw)
            logger.debug(f"<---\n{res}")
        except Exception as err:
            logger.error(f"Error parsing response: {err}")
            return None

        if res.hdr.ret != OK:
            logger.error(f"Command failed! (ret: {res.hdr.ret}) {res.hdr.err_msg}")

        return res

    def ping(self) -> dict:
        """
        Send ping to ESP32.
        Returns:
            dict: Dictionary containing pong string
        """
        resp_dict = {
            'data': {}, 'status': 'Ok'
        }

        req = request()
        res = self.send_cmd(req, PING)
        if res is not None:
            if res.hdr.ret == OK:
                resp_dict['data']['ping'] = res.ping.pong
            else:
                logger.error(f"Command failed: ({res.hdr.ret }) {res.hdr.err_msg}")
                resp_dict['status']['Error'] = res.hdr.err_msg

        return resp_dict

    def version_get(self) -> dict:
        """
        Retrieve version information from ESP32.
        Returns:
            dict: Dictionary containing version, branch, sha1, and commit date.
        """
        resp_dict = {
            'data': {}, 'status': 'Ok'
        }

        req = request()
        res = self.send_cmd(req, VERSION_GET)
        if res is not None:
            if res.hdr.ret == OK:
                resp_dict['data']['version'] = res.version_get.version
                resp_dict['data']['branch'] = res.version_get.branch
                resp_dict['data']['sha1'] = res.version_get.sha1
                resp_dict['data']['commit_date'] = res.version_get.commit_date
            else:
                logger.error(f"Command failed: ({res.hdr.ret }) {res.hdr.err_msg}")
                resp_dict['status']['Error'] = res.hdr.err_msg

        return resp_dict

    def adc_channels_get(self) -> dict:
        """
        Get available ADC channels from ESP32.
        Returns:
            dict: Dictionary containing list of ADC channels.
        """
        resp_dict = {
            'data': {}, 'status': 'Ok'
        }

        req = request()
        res = self.send_cmd(req, ADC_CHS_GET)
        if res is not None:
            if res.hdr.ret == OK:
                resp_dict['data']['adc_chs'] = res.adc_chs_get.adc_chs
            else:
                logger.error(f"Command failed: ({res.hdr.ret }) {res.hdr.err_msg}")
                resp_dict['status']['Error'] = res.hdr.err_msg

        return resp_dict

    def adc_channel_read(self, ch: int) -> dict:
        """
        Read the value from a specific ADC channel.
        Args:
            ch (int): ADC channel number.
        Returns:
            dict: Dictionary containing the ADC value.
        """
        resp_dict = {
            'data': {}, 'status': 'Ok'
        }

        req = request()
        req.adc_ch_read.ch = ch
        res = self.send_cmd(req, ADC_CH_READ)
        if res is not None:
            if res.hdr.ret == OK:
                resp_dict['data']['adc_val'] = res.adc_ch_read.val
            else:
                logger.error(f"Command failed: ({res.hdr.ret }) {res.hdr.err_msg}")
                resp_dict['status']['Error'] = res.hdr.err_msg

        return resp_dict

    def pwm_chs_get(self) -> dict:
        """
        Get available PWM channels from ESP32.
        Returns:
            dict: Dictionary containing list of PWM channels.
        """
        resp_dict = {
            'data': {}, 'status': 'Ok'
        }

        pwm_chs = 0
        req = request()
        res = self.send_cmd(req, PWM_CHS_GET)
        if res is not None:
            if res.hdr.ret == OK:
                resp_dict['data']['pwm_chs'] = res.pwm_chs_get.pwm_chs
            else:
                logger.error(f"Command failed: ({res.hdr.ret }) {res.hdr.err_msg}")
                resp_dict['status']['Error'] = res.hdr.err_msg

        return resp_dict

    def pwm_get(self, ch: int) -> dict:
        """
        Retrieve PWM period and pulse values for a specific channel.
        Args:
            ch (int): PWM channel number.
        Returns:
            dict: Dictionary containing period and pulse values.
        """
        resp_dict = {
            'data': {}, 'status': 'Ok'
        }

        pwm_val = 0
        req = request()
        req.pwm_ch_get.ch = ch
        res = self.send_cmd(req, PWM_CH_GET)
        if res is not None:
            if res.hdr.ret == OK:
                resp_dict['data']['period'] = res.pwm_ch_get.period
                resp_dict['data']['pulse'] = res.pwm_ch_get.pulse
            else:
                logger.error(f"Command failed: ({res.hdr.ret }) {res.hdr.err_msg}")
                resp_dict['status']['Error'] = res.hdr.err_msg

        return resp_dict

    def pwm_set(self, ch: int, period: int, pulse: int) -> dict:
        """
        Set PWM period and pulse for a specific channel.
        Args:
            ch (int): PWM channel number.
            period (int): PWM period value.
            pulse (int): PWM pulse value.
        Returns:
            dict: Status dictionary indicating success or error.
        """
        resp_dict = {
            'data': {}, 'status': 'Ok'
        }

        req = request()
        req.pwm_ch_set.ch = ch
        req.pwm_ch_set.period = period
        req.pwm_ch_set.pulse = pulse
        res = self.send_cmd(req, PWM_CH_SET)
        if res is not None:
            if res.hdr.ret != OK:
                logger.error(f"Command failed: ({res.hdr.ret }) {res.hdr.err_msg}")
                resp_dict['status']['Error'] = res.hdr.err_msg

        return resp_dict

    def pwm_periods_get(self) -> dict:
        """
        Get minimum and maximum PWM period values supported by ESP32.
        Returns:
            dict: Dictionary containing min and max period values.
        """
        resp_dict = {
            'data': {}, 'status': 'Ok'
        }

        req = request()
        res = self.send_cmd(req, PWM_PERIOD_INTERVAL_GET)
        if res is not None:
            if res.hdr.ret == OK:
                resp_dict['data']['min'] = res.pwm_periods_get.period_min
                resp_dict['data']['max'] = res.pwm_periods_get.period_max
            else:
                logger.error(f"Command failed: ({res.hdr.ret }) {res.hdr.err_msg}")
                resp_dict['status']['Error'] = res.hdr.err_msg

        return resp_dict

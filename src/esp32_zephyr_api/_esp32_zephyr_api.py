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

    def version_get(self) -> dict:
        resp_dict = {
            'data': {}, 'status': {'ret': ''}
        }

        req = request()
        res = self.send_cmd(req, VERSION_GET)
        if res is not None:
            if res.hdr.ret == OK:
                resp_dict['data']['version'] = res.version_get.version
                resp_dict['data']['branch'] = res.version_get.branch
                resp_dict['data']['sha1'] = res.version_get.sha1
                resp_dict['data']['commit_date'] = res.version_get.commit_date
                resp_dict['status']['ret'] = 'OK'
            else:
                logger.error(f"Command failed: ({res.hdr.ret }) {res.hdr.err_msg}")
                resp_dict['status']['ret'] = 'Error'
                resp_dict['status']['err_msg'] = res.hdr.err_msg

        return resp_dict

    def adc_channels_get(self) -> dict:
        resp_dict = {
            'data': {}, 'status': {'ret': ''}
        }

        req = request()
        res = self.send_cmd(req, ADC_CHS_GET)
        if res is not None:
            if res.hdr.ret == OK:
                resp_dict['data']['adc_chs'] = res.adc_chs_get.adc_chs
                resp_dict['status']['ret'] = 'OK'
            else:
                logger.error(f"Command failed: ({res.hdr.ret }) {res.hdr.err_msg}")
                resp_dict['status']['ret'] = 'Error'
                resp_dict['status']['err_msg'] = res.hdr.err_msg

        return resp_dict

    def adc_channel_read(self, ch: int) -> dict:
        resp_dict = {
            'data': {}, 'status': {'ret': ''}
        }

        req = request()
        req.adc_ch_read.ch = ch
        res = self.send_cmd(req, ADC_CH_READ)
        if res is not None:
            if res.hdr.ret == OK:
                resp_dict['data']['adc_val'] = res.adc_ch_read.val
            else:
                logger.error(f"Command failed: ({res.hdr.ret }) {res.hdr.err_msg}")
                resp_dict['status']['ret'] = 'Error'
                resp_dict['status']['err_msg'] = res.hdr.err_msg

        return resp_dict

    def pwm_chs_get(self) -> dict:
        resp_dict = {
            'data': {}, 'status': {'ret': ''}
        }

        pwm_chs = 0
        req = request()
        res = self.send_cmd(req, PWM_CHS_GET)
        if res is not None:
            if res.hdr.ret == OK:
                resp_dict['data']['pwm_chs'] = res.pwm_chs_get.pwm_chs
            else:
                logger.error(f"Command failed: ({res.hdr.ret }) {res.hdr.err_msg}")
                resp_dict['status']['ret'] = 'Error'
                resp_dict['status']['err_msg'] = res.hdr.err_msg

        return resp_dict

    def pwm_get(self, ch: int) -> dict:
        resp_dict = {
            'data': {}, 'status': {'ret': ''}
        }

        adc_val = 0
        req = request()
        req.adc_ch_read.ch = ch
        res = self.send_cmd(req, PWM_CH_GET)
        if res is not None:
            if res.hdr.ret == OK:
                resp_dict['data']['adc_val'] = res.adc_ch_read.val
            else:
                logger.error(f"Command failed: ({res.hdr.ret }) {res.hdr.err_msg}")
                resp_dict['status']['ret'] = 'Error'
                resp_dict['status']['err_msg'] = res.hdr.err_msg

        return resp_dict

    def pwm_set(self, ch: int, period: int, pulse: int) -> dict:
        resp_dict = {
            'data': {}, 'status': {'ret': ''}
        }

        req = request()
        req.pwm_ch_set.ch = ch
        req.pwm_ch_set.period = period
        req.pwm_ch_set.pulse = pulse
        res = self.send_cmd(req, PWM_CH_SET)
        if res is not None:
            if res.hdr.ret != OK:
                logger.error(f"Command failed: ({res.hdr.ret }) {res.hdr.err_msg}")
                resp_dict['status']['ret'] = 'Error'
                resp_dict['status']['err_msg'] = res.hdr.err_msg

        return resp_dict

    def pwm_periods_get(self) -> dict:
        resp_dict = {
            'data': {}, 'status': {'ret': ''}
        }

        req = request()
        res = self.send_cmd(req, PWM_PERIOD_INTERVAL_GET)
        if res is not None:
            if res.hdr.ret == OK:
                resp_dict['data']['min'] = res.pwm_periods_get.period_min
                resp_dict['data']['max'] = res.pwm_periods_get.period_max
            else:
                logger.error(f"Command failed: ({res.hdr.ret }) {res.hdr.err_msg}")
                resp_dict['status']['ret'] = 'Error'
                resp_dict['status']['err_msg'] = res.hdr.err_msg

        return resp_dict

from scapy.all import *
import logging
from datetime import datetime

logging.basicConfig(filename='logs.txt', level=logging.DEBUG)
logging.info('Information message')
info = '$K\xfe|@\x06\x00\xe0L6\x00|\x08\x00E\x00\x010*\xf1@\x00@\x11\x8a|\xc0\xa8\x01\xba\xc0\xa8\x01E\x85\xfe\x0b\xba\x01\x1c\xa8D/message\x00\x00\x00\x00,s\x00\x00Mavic 2 Enterprise_298CGBKR0A0A48;35263;0;-0.33000001311302185;19.0;0;0.03999999910593033;304;0;0.0;30.4547293522201;0.07999999821186066;0.0;60.0147392707197;60.0146934340961;30.4546262198169;1358850803332;1358850805.406519;2.299999952316284;8922021457590ad9;\x00'
delimiter = ' ========================================================================================================== '
info0 = b'$K\xfe|@\x06\x00\xe0L6\x00|\x08\x00E\x00\x00\xc4zB@\x00@\x11;\x97\xc0\xa8\x01\xba\xc0\xa8\x01E\x85\xfe\x0b\xba\x00\xb0?x/message\x00\x00\x00\x00,s\x00\x00Mavic 2 Enterprise_298CGBKR0A0A48;36423;0;0.0;65519.0;0;0.0;178;0;0.0;0.0;0.0;0.0;0.0;0.0;0.0;1358860412081;1358860413.4111269;0.0;8922021457590ad9;\x00\x00\x00\x00'

# found = re.findall(r'([0-9/.]*) + ;', info)
# print(found)
# for i in found:
#     if len(i) == 0:
#         found.remove(i)
#
# print(found)
# cords = {'pult': [], 'dron': [], 'height': []}

while True:
    pkts = sniff(count=1, filter="host 192.168.1.186", prn=lambda x: x.summary())
    data = pkts[0].load
    print(data.decode())

    # print(raw(pkts[0]))
    # print(len(raw(pkts[0])))
    # print(len(info))
    found = re.findall(r'([A-Za-z0-9_ \s/.]+);', str(data))
    # ff = re.match(';',data )
    # for i in found:
    #     if len(i) == 0:
    #         found.remove(i)

    print(found)
#     logging.info(delimiter + str(datetime.now()) + delimiter)
#     logging.info(raw(pkts[0]))

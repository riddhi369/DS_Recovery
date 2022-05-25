# This custom command is used to segeregate billing events hourly
import splunk.Intersplunk
import math

results = splunk.Intersplunk.readResults(None, None, True)

output = []

for result in results:
       fields = list(result.keys())
       totalHours = math.ceil(float(result['count']))
       instanceType = result['instance_hour_cur.instance_type']
       curDate = float(result['_time']) + 1800
       instanceType = result['instance_hour_cur.instance_type']
       
       for rows in range(int(totalHours)):
              cur_row = {'count': "1", 'instance_hour_cur.UsageAmount': "1", 'instance_hour_cur.instance_type': instanceType , "_time":curDate }
              output.append(cur_row)
              curDate = curDate + 3600

splunk.Intersplunk.outputResults(output)

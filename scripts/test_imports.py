import sys
sys.path.insert(0, '.')
try:
    from raphael.eventbus import EventBus, EventBusConfig
    print('eventbus OK')
except Exception as e:
    print(f'eventbus: {e}')

try:
    from raphael.blackboard import Blackboard
    print('blackboard OK')
except Exception as e:
    print(f'blackboard: {e}')
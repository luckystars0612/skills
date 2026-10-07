# Robot-Specific Analysis

Techniques for analyzing robot-specific components: ROS/ROS2, robotics protocols (DDS, MQTT, CAN, EtherCAT, Modbus), motor controllers, sensor interfaces, safety-critical code, and platform-specific knowledge.

---

## ROS (Robot Operating System) Analysis

### ROS1 Detection and Enumeration

```bash
# Find ROS packages
find . -name 'package.xml' 2>/dev/null | while read pkg; do
    name=$(grep '<name>' "$pkg" | sed 's/.*<name>\(.*\)<\/name>.*/\1/')
    echo "$pkg → $name"
done

# Find launch files
find . -name '*.launch' 2>/dev/null | head -20

# Find message/service/action definitions
find . -name '*.msg' -o -name '*.srv' -o -name '*.action' 2>/dev/null | head -20

# ROS node binaries
find . -path '*/lib/*/node_*' -o -path '*/lib/*/*.py' 2>/dev/null | head -20

# ROS configuration (parameters, topics)
grep -rI 'ros::param\|ros::NodeHandle\|getParam\|setParam\|advertise\|subscribe' . 2>/dev/null | head -20

# ROS master URI (often hardcoded)
grep -rI 'ROS_MASTER_URI' . 2>/dev/null
strings <binary> | grep -i 'ros_master\|11311' | head -5
```

### ROS2 Detection and Enumeration

```bash
# ROS2 packages
find . -name 'package.xml' 2>/dev/null | while read pkg; do
    if grep -q 'ament\|ros2\|rclcpp\|rclpy' "$pkg" 2>/dev/null; then
        name=$(grep '<name>' "$pkg" | sed 's/.*<name>\(.*\)<\/name>.*/\1/')
        echo "[ROS2] $pkg → $name"
    fi
done

# ROS2 launch files
find . -name '*.launch.py' -o -name '*.launch.xml' -o -name '*.launch.yaml' 2>/dev/null | head -20

# ROS2 interfaces
find . -name '*.msg' -o -name '*.srv' -o -name '*.action' 2>/dev/null | head -20

# ROS2 parameter files
find . -name '*.param' -o -name '*.yaml' -path '*/config/*' 2>/dev/null | head -20

# DDS domain ID (default 0)
grep -rI 'ROS_DOMAIN_ID\|domain_id' . 2>/dev/null | head -10
```

### ROS/ROS2 Security Assessment

**SROS2 (Secure ROS2) checks:**

```bash
# Check for SROS2 security configuration
find . -name 'permissions.xml' -o -name 'governance.xml' -o -name 'enclave' \
       -o -name 'permissions_ca.cert.pem' 2>/dev/null | head -10

# SROS2 keystore
find . -path '*/keystore/*' 2>/dev/null | head -20
find . -name 'identity_ca.cert.pem' -o -name 'permissions_ca.cert.pem' 2>/dev/null

# Check if security is actually enabled
grep -rI 'ROS_SECURITY_ENABLE\|ROS_SECURITY_STRATEGY\|SECURITY' . 2>/dev/null | head -10
# ROS_SECURITY_ENABLE=true → security enabled
# ROS_SECURITY_STRATEGY=Enforce → must authenticate (good)
# ROS_SECURITY_STRATEGY=Permissive → falls back to insecure (bad)
```

**Common ROS vulnerability patterns:**

| Vulnerability | Pattern | Impact |
|--------------|---------|--------|
| Unauthenticated topics | No SROS2, default DDS | Anyone on network can publish/subscribe |
| Unprotected services | Services without auth | Remote command execution via service calls |
| Parameter tampering | Parameters without validation | Modify robot behavior (speed, limits) |
| Launch file injection | Dynamic launch file paths | Code execution via modified launch files |
| URDF manipulation | Unsigned URDF models | Modify robot kinematics (safety impact) |
| Message type confusion | Custom message types without validation | Type confusion attacks |

```bash
# Check for unprotected topics
# Look for safety-critical topics without security
grep -rI 'cmd_vel\|joint_command\|trajectory\|moveit\|twist\|wrench' . 2>/dev/null | head -10

# Check for service calls that could be dangerous
grep -rI 'create_service\|advertise_service' . 2>/dev/null | head -10

# URDF files (robot description — safety critical)
find . -name '*.urdf' -o -name '*.xacro' 2>/dev/null | head -10
```

---

## DDS (Data Distribution Service) Analysis

### DDS Implementation Identification

```bash
# Identify DDS implementation
strings <binary> | grep -iE '(fastdds|fast-dds|fast.rtps|cyclonedds|cyclone|rti.dds|connext|opendds|coredx)' | head -10

# DDS libraries
find . -name '*fastdds*' -o -name '*fastrtps*' -o -name '*cyclone*' \
       -o -name '*connext*' -o -name '*opendds*' 2>/dev/null | head -10

# RMW (ROS2 middleware) implementation
grep -rI 'rmw_fastrtps\|rmw_cyclonedds\|rmw_connext' . 2>/dev/null | head -5
```

### RTPS Discovery Analysis

```bash
# RTPS uses multicast for discovery (port 7400+)
# Domain participants discover each other automatically

# Check DDS configuration files
find . -name '*dds*profile*' -o -name '*fastdds*' -o -name '*cyclone*.xml' \
       -o -name 'DEFAULT_FASTRTPS_PROFILES.xml' 2>/dev/null | head -10

# DDS domain ID (determines multicast group)
grep -rI 'domain_id\|domainId\|DOMAIN_ID' . 2>/dev/null | head -5

# DDS QoS settings (Quality of Service)
grep -rI 'reliability\|durability\|deadline\|lifespan\|liveliness' . 2>/dev/null | head -10
```

### DDS Security Audit

```bash
# DDS Security plugins
grep -rI 'dds.sec\|security\|authentication\|access_control\|crypto' . 2>/dev/null | grep -i dds | head -10

# Security-relevant QoS:
# - No authentication → anyone can join domain
# - No access control → any participant can pub/sub any topic
# - No encryption → all data in plaintext on network

# DDS security certificates
find . -name '*identity_ca*' -o -name '*permissions_ca*' -o -name '*governance*' \
       -o -name '*cert.pem' -path '*dds*' 2>/dev/null | head -10

# Default DDS configurations (often insecure)
# FastDDS: no security by default
# CycloneDDS: no security by default
# RTI Connext: security plugins available but optional
```

---

## Industrial Protocol Analysis

### MQTT Analysis

```bash
# MQTT broker detection
find . -name 'mosquitto.conf' -o -name '*mqtt*.conf' -o -name '*broker*.conf' 2>/dev/null
strings <binary> | grep -iE '(mqtt|mosquitto|emqx|hivemq|broker)' | head -10

# MQTT configuration audit
for conf in $(find . -name 'mosquitto.conf' -o -name '*mqtt*.conf' 2>/dev/null); do
    echo "=== $conf ==="
    # Check for security settings
    grep -E '(allow_anonymous|password_file|acl_file|psk_file|cafile|certfile|keyfile|listener|port|protocol)' "$conf" 2>/dev/null
done

# MQTT topics in binary
strings <binary> | grep -E '^[a-zA-Z0-9_]+(/[a-zA-Z0-9_#+]+)+$' | head -20

# MQTT credentials
grep -rI 'mqtt.*password\|mqtt.*user\|mqtt.*auth' . 2>/dev/null | head -10
```

**MQTT security checklist:**

| Check | Secure | Insecure |
|-------|--------|----------|
| Authentication | `allow_anonymous false` + password file | `allow_anonymous true` |
| Encryption | TLS/SSL configured (port 8883) | Plain TCP (port 1883) |
| ACL | ACL file with topic restrictions | No ACL (full access) |
| Protocol | MQTT v5 with enhanced auth | MQTT v3.1.1 without auth |

### CAN Bus Analysis

```bash
# CAN interface detection
strings <binary> | grep -iE '(socketcan|can[0-9]|vcan|canopen|j1939|iso.?tp|uds)' | head -10

# CAN bus configuration
find . -name '*.dbc' -o -name '*.eds' -o -name '*.dcf' 2>/dev/null | head -10

# DBC file analysis (CAN database)
for dbc in $(find . -name '*.dbc' 2>/dev/null); do
    echo "=== $dbc ==="
    grep -E '^(BO_|SG_|CM_)' "$dbc" | head -20  # Messages, signals, comments
done

# CANopen detection
strings <binary> | grep -iE '(canopen|node.?id|sdo|pdo|nmt|heartbeat|0x[0-9a-f]{3})' | head -10

# UDS (Unified Diagnostic Services) — vehicle/robot diagnostics
strings <binary> | grep -iE '(diagnostic|uds|0x10|0x11|0x27|0x31|0x34|0x36|security.access)' | head -10
# 0x27 = SecurityAccess (auth bypass target)
# 0x31 = RoutineControl
# 0x34/0x36 = RequestDownload/TransferData (firmware update)
```

**CAN bus security notes:**
- CAN has **no authentication** — any device on the bus can send any message
- Arbitration ID spoofing is trivial
- Safety-critical messages (e-stop, brake) are high priority (low ID)
- A compromised node can DoS by flooding with high-priority frames

**Note:** `can-utils` may not be installed. Install with: `sudo apt install can-utils`

### EtherCAT Analysis

```bash
# EtherCAT detection
strings <binary> | grep -iE '(ethercat|ecrt|esi|mailbox|fmmu|sync.?manager|pdo.?mapping)' | head -10

# ESI (EtherCAT Slave Information) XML files
find . -name '*.xml' -exec grep -l 'EtherCAT\|ESI\|Slave' {} \; 2>/dev/null | head -10

# EtherCAT master configuration
find . -name '*ethercat*' -o -name '*ec_*' 2>/dev/null | head -10

# PDO (Process Data Object) mappings — what data is exchanged
grep -rI 'RxPdo\|TxPdo\|SM[0-9]\|FMMU' . 2>/dev/null | head -10
```

### Modbus Analysis

```bash
# Modbus detection
strings <binary> | grep -iE '(modbus|modbus.tcp|modbus.rtu|coil|holding.register|input.register|function.code)' | head -10

# Modbus configuration
find . -name '*modbus*' 2>/dev/null | head -10

# Modbus register mappings
grep -rI 'register\|coil\|discrete\|holding\|input' . 2>/dev/null | grep -i modbus | head -10

# Modbus port (default 502 TCP, 502 RTU over serial)
strings <binary> | grep '502' | head -5
```

**Modbus security notes:**
- Modbus has **no authentication or encryption** by default
- All function codes accessible to any client
- Register read/write = direct control of physical process
- Modbus TCP on port 502 is a common attack vector for ICS

### OPC UA Analysis

```bash
# OPC UA detection
strings <binary> | grep -iE '(opc.ua|opcua|open62541|freeopcua|node-opcua|opc.tcp)' | head -10

# OPC UA security
grep -rI 'SecurityPolicy\|MessageSecurityMode\|UserTokenPolicy' . 2>/dev/null | head -10
# SecurityPolicy.None = no encryption
# MessageSecurityMode.None = no signing

# OPC UA certificates
find . -name '*.der' -o -name '*.pem' -path '*opcua*' 2>/dev/null | head -10
```

### PROFINET / EtherNet/IP

```bash
# PROFINET detection
strings <binary> | grep -iE '(profinet|pnio|gsdml|dcerpc)' | head -10

# EtherNet/IP detection
strings <binary> | grep -iE '(ethernet.ip|cip|enip|rockwell|allen.bradley)' | head -10
```

---

## Motor Controller Firmware Analysis

### PID Parameters and Safety Limits

```bash
# PID parameters
strings <binary> | grep -iE '(pid|kp|ki|kd|proportional|integral|derivative|gain)' | head -10
grep -rI 'pid\|kp\|ki\|kd' . 2>/dev/null | grep -v '.git' | head -20

# Safety limits
strings <binary> | grep -iE \
  '(max.vel|max.speed|velocity.limit|speed.limit|
    max.torque|torque.limit|current.limit|
    max.accel|acceleration.limit|
    workspace.limit|joint.limit|
    position.limit|angle.limit|
    force.limit|payload|
    max.temp|temperature.limit|
    timeout|watchdog)' | head -20

# Motor parameters
strings <binary> | grep -iE \
  '(motor|servo|drive|encoder|resolver|hall|
    pwm|duty.cycle|frequency|
    brake|clutch|gear|ratio)' | head -10
```

### E-Stop Implementation

```bash
# Emergency stop analysis
strings <binary> | grep -iE '(e.stop|estop|emergency|halt|safe.stop|sto|ss1|ss2|sls|sbc)' | head -10

# E-stop in code
grep -rI 'estop\|e_stop\|emergency_stop\|EMERGENCY\|STO\|SafeStop' . 2>/dev/null | head -20

# Hardware e-stop pins
strings <binary> | grep -iE '(gpio.*stop\|pin.*emergency\|estop.*pin\|safety.*input)' | head -5

# Safety function codes (IEC 61800-5-2)
# STO: Safe Torque Off
# SS1: Safe Stop 1
# SS2: Safe Stop 2
# SLS: Safely Limited Speed
# SBC: Safe Brake Control
# SDI: Safe Direction
# SLI: Safely Limited Increment
```

### Watchdog Configuration

```bash
# Watchdog timer
strings <binary> | grep -iE '(watchdog|wdt|iwdg|wwdg|kick|feed|pet)' | head -10

# Watchdog configuration in code
grep -rI 'watchdog\|WDT\|IWDG\|WWDG' . 2>/dev/null | head -10

# Watchdog timeout values
strings <binary> | grep -iE 'wdt.*[0-9]+\|watchdog.*ms\|timeout.*[0-9]+' | head -5
```

### Servo Drive State Machine (CANopen DS402)

```bash
# DS402 state machine states
strings <binary> | grep -iE \
  '(not.ready|switch.on.disabled|ready.to.switch|switched.on|
    operation.enabled|quick.stop|fault.reaction|fault)' | head -10

# DS402 control word / status word
strings <binary> | grep -iE '(controlword|statusword|0x6040|0x6041)' | head -5

# Operating modes
strings <binary> | grep -iE \
  '(profile.position|profile.velocity|profile.torque|
    homing|interpolated.position|cyclic.sync)' | head -10
```

---

## Sensor Interface Analysis

### LiDAR

```bash
# LiDAR vendor detection
strings <binary> | grep -iE \
  '(velodyne|ouster|sick|hokuyo|rplidar|livox|hesai|robosense|
    lidar|laser.scan|point.cloud|pcl)' | head -10

# LiDAR configuration
find . -name '*lidar*' -o -name '*laser*' -o -name '*velodyne*' -o -name '*ouster*' 2>/dev/null | head -10

# LiDAR network configuration (many use UDP)
strings <binary> | grep -iE '(2368|2369|7502|9346)' | head -5  # Common LiDAR ports
```

### Camera

```bash
# Camera interface detection
strings <binary> | grep -iE \
  '(mipi|csi|gige.vision|usb.cam|v4l2|opencv|
    realsense|zed|kinect|basler|flir|ids)' | head -10

# Camera configuration
find . -name '*camera*' -o -name '*vision*' 2>/dev/null | head -10

# GigE Vision (network cameras)
strings <binary> | grep -iE '(gige|gvcp|gvsp|3956)' | head -5
```

### IMU / Force-Torque / Proximity

```bash
# IMU sensors
strings <binary> | grep -iE '(imu|accel|gyro|magnetometer|mpu[0-9]|bno|lsm[0-9]|icm[0-9])' | head -10

# Force/torque sensors
strings <binary> | grep -iE '(force.torque|ft.sensor|ati|optoforce|robotiq|load.cell)' | head -10

# Proximity/safety sensors
strings <binary> | grep -iE '(proximity|ultrasonic|infrared|safety.scanner|light.curtain|area.scanner)' | head -10
```

---

## Safety-Critical Code Analysis

### Safety Function Identification

```bash
# Safety-related functions and variables
strings <binary> | grep -iE \
  '(safety|safe_|_safe|protect|guard|limit|check|verify|validate|
    redundant|watchdog|heartbeat|alive|monitor|supervisor|
    fault|error|alarm|warning|emergency)' | head -30

# Dual-channel / redundancy patterns
grep -rI 'channel_a\|channel_b\|primary\|secondary\|redundant\|voter\|compare' . 2>/dev/null | head -10

# Cyclic safety checks
strings <binary> | grep -iE '(cycle_time\|scan_time\|period\|deadline\|jitter)' | head -10
```

### Safety Standards Compliance Indicators

```bash
# IEC 61508 / ISO 13849 markers
strings <binary> | grep -iE '(sil[1-4]|sil_[1-4]|pl_[a-e]|performance.level|safety.integrity|category_[1-4])' | head -10

# IEC 62443 (industrial cybersecurity)
strings <binary> | grep -iE '(iec.62443|sl_[0-4]|security.level|zone|conduit)' | head -10

# Functional safety
grep -rI 'SAFETY\|SAFE_STATE\|FAULT_REACTION\|SAFE_TORQUE_OFF' . 2>/dev/null | head -10
```

### Watchdog Bypass Analysis

```bash
# Watchdog feeding patterns
# Look for functions that write to watchdog registers
# If watchdog can be disabled or fed from untrusted code → safety risk

# Check if watchdog is software-disableable
strings <binary> | grep -iE '(disable.*watchdog\|watchdog.*disable\|wdt.*off\|stop.*wdt)' | head -5

# Window watchdog (must be fed within time window, not just before timeout)
strings <binary> | grep -iE '(window.*wdt\|wwdg\|window.*watchdog)' | head -5
```

### Task Priority Analysis (RTOS)

```bash
# Safety tasks should have highest priority
# Look for task creation with priority parameters
strings <binary> | grep -iE '(priority|prio|task.*create)' | head -10

# FreeRTOS: configMAX_PRIORITIES, higher number = higher priority
# VxWorks: 0 = highest, 255 = lowest
# QNX: 1 = lowest, 255 = highest

# Check if safety task priority is highest
grep -rI 'SAFETY.*PRIORITY\|PRIORITY.*SAFETY\|safety.*prio' . 2>/dev/null | head -5
```

---

## Robot Platform-Specific Knowledge

### Universal Robots (UR)

```bash
# UR detection
strings <binary> | grep -iE '(universal.robot|urscript|ur[0-9]|ur[0-9]e|polyscope)' | head -10

# UR network ports
# 30001: Primary client interface (state data)
# 30002: Secondary client interface
# 30003: Real-time client interface (125 Hz)
# 30004: RTDE (Real-Time Data Exchange)
# 29999: Dashboard server
# 502: Modbus TCP

# URScript commands (can control robot remotely)
strings <binary> | grep -iE '(movej|movel|movep|speedj|speedl|servoj|force_mode|freedrive)' | head -10

# UR safety configuration
strings <binary> | grep -iE '(safety.mode|protective.stop|safeguard|reduced.mode)' | head -10
```

### ABB (RAPID)

```bash
# ABB detection
strings <binary> | grep -iE '(abb|rapid|robotstudio|irc5|omnicore|flexpendant)' | head -10

# RAPID language commands
strings <binary> | grep -iE '(MoveAbsJ|MoveJ|MoveL|MoveC|SpeedData|AccelData)' | head -10
```

### KUKA (KRL)

```bash
# KUKA detection
strings <binary> | grep -iE '(kuka|krl|sunrise|smartpad|iiwa|lbr)' | head -10

# KRL commands
strings <binary> | grep -iE '(PTP|LIN|CIRC|SPLINE|FOLD|TRIGGER)' | head -10
```

### Fanuc (KAREL)

```bash
# Fanuc detection
strings <binary> | grep -iE '(fanuc|karel|tp_program|teach.pendant)' | head -10
```

### DJI Drones

```bash
# DJI detection
strings <binary> | grep -iE '(dji|phantom|mavic|matrice|inspire|robomaster)' | head -10

# DJI firmware structure
strings <binary> | grep -iE '(dji.*fw\|firmware.*version\|nfz\|geofence\|no.fly)' | head -10
```

### AGV/AMR Navigation

```bash
# Navigation stack
strings <binary> | grep -iE '(nav2|move_base|navigation|slam|amcl|costmap|path.plan|dwa|teb)' | head -10

# Map files
find . -name '*.pgm' -o -name '*.yaml' -path '*map*' 2>/dev/null | head -10

# Localization
strings <binary> | grep -iE '(amcl|cartographer|rtabmap|orb.slam|lidar.slam)' | head -10
```

### Cobots (Collaborative Robots)

```bash
# Cobot safety features
strings <binary> | grep -iE \
  '(force.limit|power.limit|speed.limit|momentum.limit|
    collision.detect|contact.detect|
    power.force.limit|pfl|
    iso.10218|iso.15066|ts.15066|
    cobot|collaborative)' | head -10

# ISO 15066 compliance markers
strings <binary> | grep -iE '(quasi.static|transient|body.model|pain.threshold)' | head -5
```

---

## Robot-Specific Vulnerability Patterns

### Safety System Attacks

| Attack | Target | Impact | Detection |
|--------|--------|--------|-----------|
| E-stop bypass | E-stop GPIO/CAN message | Loss of emergency stop | Check e-stop is hardware-wired |
| Speed limit override | Safety controller parameters | Robot exceeds safe speed | Check parameter write protection |
| Workspace violation | Joint/position limits | Robot moves outside safe zone | Check limit enforcement |
| Force limit bypass | Torque/force limiter | Cobot injures human | Check force limiting is hardware-based |
| Watchdog defeat | Watchdog timer feed | Safety monitoring disabled | Check watchdog is independent hardware |

### Communication Attacks

| Attack | Protocol | Impact | Detection |
|--------|----------|--------|-----------|
| Topic injection | ROS/DDS | Control robot motion | Check for SROS2/DDS security |
| CAN spoofing | CAN bus | Send false commands | Check for CAN authentication |
| Modbus write | Modbus | Modify register values | Check for Modbus authentication |
| MQTT injection | MQTT | Publish false sensor data | Check for MQTT ACL/auth |
| OPC UA exploit | OPC UA | Read/write variables | Check security policy |

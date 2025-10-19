
# Tatou Quick Response Checklist
# Rapid assessment tool for security incidents

set -e

echo " Tatou Security Quick Response Checklist"
echo "=========================================="
echo "Timestamp: $(date -Iseconds)"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

check_service() {
    local service=$1
    if docker compose ps $service | grep -q "Up"; then
        echo -e "${GREEN}✅${NC} $service: Running"
        return 0
    else
        echo -e "${RED}❌${NC} $service: NOT RUNNING"
        return 1
    fi
}

check_endpoint() {
    local name=$1
    local url=$2
    if curl -s --connect-timeout 5 "$url" > /dev/null; then
        echo -e "${GREEN}✅${NC} $name: Accessible"
        return 0
    else
        echo -e "${RED}❌${NC} $name: INACCESSIBLE"
        return 1
    fi
}

check_logs() {
    local service=$1
    local pattern=$2
    echo -e "${YELLOW}🔍${NC} Checking $service logs for: $pattern"
    docker compose logs $service | tail -50 | grep -i "$pattern" | head -5 || echo "  No recent matches found"
}

echo "1. SERVICE STATUS CHECK"
echo "----------------------"
check_service server
check_service db
check_service prometheus
check_service grafana

echo ""
echo "2. ENDPOINT ACCESSIBILITY"
echo "------------------------"
check_endpoint "Application" "http://localhost:5000/healthz"
check_endpoint "Prometheus" "http://localhost:9090/-/healthy"
check_endpoint "Grafana" "http://localhost:3000/api/health"

echo ""
echo "3. SECURITY EVENT SCAN"
echo "---------------------"
check_logs server "security"
check_logs server "error"
check_logs server "failed"
check_logs server "unauthorized"

echo ""
echo "4. FLAG STATUS CHECK"
echo "-------------------"
# Check container flag
if docker exec tatou-server-1 test -f /app/flag 2>/dev/null; then
    echo -e "${GREEN}✅${NC} Container flag: Present"
    flag_content=$(docker exec tatou-server-1 head -c 50 /app/flag 2>/dev/null || echo "unreadable")
    echo "   Content preview: $flag_content"
else
    echo -e "${RED}❌${NC} Container flag: MISSING"
fi

# Check project flag
if test -f /tatou/flag 2>/dev/null || test -f ./flag 2>/dev/null; then
    echo -e "${GREEN}✅${NC} Project flag: Present"
else
    echo -e "${RED}❌${NC} Project flag: MISSING"
fi

echo ""
echo "5. RESOURCE USAGE"
echo "----------------"
echo "Container resource usage:"
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}" tatou-server-1 tatou-db-1 2>/dev/null || echo "  Resource stats unavailable"

echo ""
echo "6. NETWORK CONNECTIONS"
echo "---------------------"
echo "Active connections in server container:"
docker exec tatou-server-1 netstat -tun | grep ESTABLISHED | wc -l | xargs echo "  Established connections:"

echo ""
echo " QUICK RESPONSE ACTIONS"
echo "========================"
echo "If you identify issues:"
echo "1. Check detailed logs: docker compose logs -f server"
echo "2. View metrics: http://localhost:9090"
echo "3. Check dashboards: http://localhost:3000"
echo "4. Restart services: docker compose restart [service]"
echo "5. Emergency stop: docker compose down"
echo ""
echo "Assessment completed at: $(date -Iseconds)"

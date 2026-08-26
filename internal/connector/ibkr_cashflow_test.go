package connector

import (
	"strings"
	"testing"
	"time"
)

func flexReport(rows string) []byte {
	return []byte(`<FlexQueryResponse queryName="q" type="AF">
  <FlexStatements count="1">
    <FlexStatement accountId="U1234567">` + rows + `
    </FlexStatement>
  </FlexStatements>
</FlexQueryResponse>`)
}

func parseFlows(t *testing.T, rows string) ([]*Cashflow, *IBKR) {
	t.Helper()
	i := &IBKR{}
	flows, err := i.parseCashflowsFromReport(flexReport(rows), time.Time{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return flows, i
}

// The regression this file exists for. Current Flex statements spell the
// umbrella funding type "Deposits & Withdrawals"; the parser matched only the
// older slash spelling, so an ordinary wire deposit was dropped without a
// trace. The account's equity stepped up with no recorded inflow and the step
// read as a trading gain — a fresh account showed a +9,758 "gain" that was
// its own funding (2026-08-25).
func TestParseCashflows_AmpersandSpellingIsCapital(t *testing.T) {
	flows, i := parseFlows(t, `
      <CashTransactions>
        <CashTransaction type="Deposits &amp; Withdrawals" amount="9758.16" currency="USD" dateTime="20260602;093000"/>
      </CashTransactions>`)
	if len(flows) != 1 {
		t.Fatalf("got %d cashflows, want the deposit", len(flows))
	}
	if flows[0].Amount != 9758.16 {
		t.Fatalf("amount = %v, want 9758.16", flows[0].Amount)
	}
	if len(i.CapabilityWarnings()) != 0 {
		t.Fatalf("a known type raised warnings: %v", i.CapabilityWarnings())
	}
}

func TestParseCashflows_SlashSpellingStillWorks(t *testing.T) {
	flows, _ := parseFlows(t, `
      <CashTransactions>
        <CashTransaction type="Deposits/Withdrawals" amount="1000" currency="USD" dateTime="20260601;120000"/>
        <CashTransaction type="Deposits/Withdrawals" amount="-250" currency="USD" dateTime="20260603;120000"/>
      </CashTransactions>`)
	if len(flows) != 2 {
		t.Fatalf("got %d cashflows, want 2", len(flows))
	}
	if flows[0].Amount != 1000 || flows[1].Amount != -250 {
		t.Fatalf("amounts = %v/%v, want 1000/-250", flows[0].Amount, flows[1].Amount)
	}
}

// Dividends and interest are returns of holding the account. Booking them as
// deposits would erase the very performance they represent.
func TestParseCashflows_IncomeIsNotCapitalAndNotAWarning(t *testing.T) {
	flows, i := parseFlows(t, `
      <CashTransactions>
        <CashTransaction type="Dividends" amount="52.30" currency="USD" dateTime="20260610;120000"/>
        <CashTransaction type="Withholding Tax" amount="-7.85" currency="USD" dateTime="20260610;120000"/>
        <CashTransaction type="Broker Interest Received" amount="1.12" currency="USD" dateTime="20260630;120000"/>
      </CashTransactions>`)
	if len(flows) != 0 {
		t.Fatalf("income rows became cashflows: %d", len(flows))
	}
	if len(i.CapabilityWarnings()) != 0 {
		t.Fatalf("known income types raised warnings: %v", i.CapabilityWarnings())
	}
}

// A type in neither list is money whose meaning we cannot state. It stays out
// of the cashflows, but it must leave a mark someone can find — the silent
// drop is exactly what produced the phantom gain.
func TestParseCashflows_UnknownTypeLeavesAWarning(t *testing.T) {
	flows, i := parseFlows(t, `
      <CashTransactions>
        <CashTransaction type="Sales Tax" amount="-3.10" currency="USD" dateTime="20260612;120000"/>
        <CashTransaction type="Sales Tax" amount="-2.90" currency="USD" dateTime="20260613;120000"/>
      </CashTransactions>`)
	if len(flows) != 0 {
		t.Fatalf("an unclassified type was booked as capital: %d flows", len(flows))
	}
	warns := i.CapabilityWarnings()
	if len(warns) != 1 {
		t.Fatalf("warnings = %v, want exactly one", warns)
	}
	if !strings.Contains(warns[0], "Sales Tax") || !strings.Contains(warns[0], "x2") {
		t.Fatalf("warning %q should carry the type and the count", warns[0])
	}
	// Types and counts only — an amount in a warning would end up in
	// sync_statuses and on a dashboard.
	if strings.Contains(warns[0], "3.10") || strings.Contains(warns[0], "2.90") {
		t.Fatalf("warning %q leaks amounts", warns[0])
	}
}

// Cash moved between accounts (INTERNAL, ACATS) never appears under
// CashTransactions. Without the Transfers section, a user funding this
// account from another one crosses the perimeter invisibly.
func TestParseCashflows_TransferCashCrossesThePerimeter(t *testing.T) {
	flows, i := parseFlows(t, `
      <Transfers>
        <Transfer type="INTERNAL" direction="IN" cashTransfer="5000" currency="USD" dateTime="20260605;100000"/>
        <Transfer type="ACATS" direction="OUT" cashTransfer="1200" currency="USD" date="20260620"/>
      </Transfers>`)
	if len(flows) != 2 {
		t.Fatalf("got %d cashflows, want 2 transfer legs", len(flows))
	}
	if flows[0].Amount != 5000 {
		t.Fatalf("inbound = %v, want +5000", flows[0].Amount)
	}
	if flows[1].Amount != -1200 {
		t.Fatalf("outbound = %v, want -1200 regardless of how the statement signs it", flows[1].Amount)
	}
	if len(i.CapabilityWarnings()) != 0 {
		t.Fatalf("clean transfers raised warnings: %v", i.CapabilityWarnings())
	}
}

// A pure position transfer moves holdings, not cash; its market value reaches
// the curve through equity like any position. Booking it as a deposit would
// double-count it.
func TestParseCashflows_PositionOnlyTransferIsNotCash(t *testing.T) {
	flows, _ := parseFlows(t, `
      <Transfers>
        <Transfer type="FOP" direction="IN" cashTransfer="0" currency="USD" dateTime="20260607;100000"/>
      </Transfers>`)
	if len(flows) != 0 {
		t.Fatalf("a position-only transfer became a cashflow: %d", len(flows))
	}
}

func TestParseCashflows_SingularSpellingsNormalizeTheirSign(t *testing.T) {
	flows, _ := parseFlows(t, `
      <CashTransactions>
        <CashTransaction type="Deposits" amount="-500" currency="USD" dateTime="20260601;120000"/>
        <CashTransaction type="Withdrawals" amount="300" currency="USD" dateTime="20260602;120000"/>
      </CashTransactions>`)
	if len(flows) != 2 {
		t.Fatalf("got %d cashflows, want 2", len(flows))
	}
	if flows[0].Amount != 500 {
		t.Fatalf("a Deposits row must come out positive, got %v", flows[0].Amount)
	}
	if flows[1].Amount != -300 {
		t.Fatalf("a Withdrawals row must come out negative, got %v", flows[1].Amount)
	}
}

func TestParseCashflows_SinceFilterAppliesToBothSections(t *testing.T) {
	i := &IBKR{}
	report := flexReport(`
      <CashTransactions>
        <CashTransaction type="Deposits &amp; Withdrawals" amount="100" currency="USD" dateTime="20260101;120000"/>
      </CashTransactions>
      <Transfers>
        <Transfer type="INTERNAL" direction="IN" cashTransfer="200" currency="USD" dateTime="20260102;120000"/>
      </Transfers>`)
	since := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	flows, err := i.parseCashflowsFromReport(report, since)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(flows) != 0 {
		t.Fatalf("rows before the since bound leaked through: %d", len(flows))
	}
}

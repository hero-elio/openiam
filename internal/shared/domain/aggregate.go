package domain

type AggregateRoot struct {
	Version int
	events  []DomainEvent
}

func (a *AggregateRoot) RecordEvent(e DomainEvent) {
	a.events = append(a.events, e)
}

func (a *AggregateRoot) PullEvents() []DomainEvent {
	events := a.events
	a.events = nil
	return events
}
